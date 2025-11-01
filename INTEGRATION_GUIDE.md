# ZORBOX Integration Guide

This document provides integration guidelines for all team members (Backend, Frontend, AI Engineer, Network Engineer, and Solution Architect) to ensure seamless collaboration.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [API Contracts](#api-contracts)
3. [Data Schemas](#data-schemas)
4. [Integration Points](#integration-points)
5. [Environment Configuration](#environment-configuration)
6. [Error Handling](#error-handling)
7. [Testing Guidelines](#testing-guidelines)

---

## Architecture Overview

```
┌─────────────┐
│  Frontend   │ (React)
└──────┬──────┘
       │ HTTP/REST
┌──────▼──────┐
│   Backend   │ (Spring Boot) ←──┐
└──────┬──────┘                  │
       │                         │
       ├───► Redis (Job Queue)   │
       │                         │
       ├───► PostgreSQL          │ Notifications
       │                         │
       ├───► MinIO (Storage)     │
       │                         │
       └───► Orchestrator ───────┘
                  │
                  ├──► Master Analyzer
                  │       │
                  │       ├──► Strelka (Static)
                  │       ├──► Native Engine
                  │       ├──► Cuckoo (Dynamic)
                  │       └──► CAPE
                  │
                  └──► AI Service (Flask)
```

---

## API Contracts

### Backend API Endpoints (Expected by Orchestrator)

#### 1. Update Job Status
```
PUT /api/jobs/{job_id}/status
Content-Type: application/json

Request Body:
{
  "job_id": "job_1234567890_file123",
  "state": "static_analysis",
  "progress_percentage": 25,
  "results": null
}

Response: 200 OK or 204 No Content
```

#### 2. Update Job Result
```
PUT /api/jobs/{job_id}/result
Content-Type: application/json

Request Body:
{
  "job_id": "job_1234567890_file123",
  "file_info": { ... },
  "final_risk_score": 75,
  "final_risk_level": "HIGH",
  "static_analysis": { ... },
  "sandbox_analysis": { ... },
  "ai_scoring": { ... },
  "completed_at": 1234567890.123
}

Response: 200 OK or 204 No Content
```

#### 3. Get Job Status
```
GET /api/jobs/{job_id}/status

Response: 200 OK
{
  "job_id": "job_1234567890_file123",
  "state": "sandbox_analysis",
  "progress_percentage": 50,
  "current_step": "Running Cuckoo analysis",
  "created_at": 1234567890.0,
  "updated_at": 1234567890.5,
  "error_message": null
}
```

#### 4. Get Job Result
```
GET /api/jobs/{job_id}/result

Response: 200 OK
{
  "job_id": "job_1234567890_file123",
  "file_info": { ... },
  "final_risk_score": 75,
  "final_risk_level": "HIGH",
  "static_analysis": { ... },
  "sandbox_analysis": { ... },
  "ai_scoring": { ... },
  "report_pdf_url": "/api/reports/job_1234567890_file123.pdf"
}
```

#### 5. Health Check
```
GET /api/health

Response: 200 OK
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

---

### AI Service API Endpoints (Expected by Orchestrator)

#### 1. Calculate Risk Score
```
POST /score
Content-Type: application/json

Request Body:
{
  "static_analysis": {
    "file_type": "PE32",
    "file_hash": "sha256...",
    "entropy": 7.5,
    "yara_matches": ["Trojan.Win32", "Suspicious"],
    "suspicious_imports": ["CreateRemoteThread", "VirtualAllocEx"]
  },
  "sandbox_analysis": {
    "native_engine": {
      "risk_score": 65,
      "network_activity": true,
      "suspicious_behaviors": [...]
    },
    "cuckoo": {
      "risk_score": 70,
      "signatures": [...]
    }
  },
  "file_info": {
    "file_name": "sample.exe",
    "file_size": 123456,
    "file_type": "application/x-msdownload"
  }
}

Response: 200 OK
{
  "ai_score": 72,
  "confidence": 0.85,
  "explanation": [
    "High entropy detected",
    "Suspicious API imports found",
    "Network activity observed"
  ],
  "feature_importance": {
    "yara_matches": 0.35,
    "entropy": 0.25,
    "network_activity": 0.20,
    "suspicious_imports": 0.20
  },
  "model_version": "v1.2.0"
}
```

#### 2. Health Check
```
GET /health

Response: 200 OK
{
  "status": "healthy",
  "model_loaded": true
}
```

---

## Data Schemas

All schemas are defined in `orchestrator/schemas.py`. Key schemas:

### JobState Enum
```python
PENDING = "pending"
DOWNLOADING = "downloading"
STATIC_ANALYSIS = "static_analysis"
SANDBOX_ANALYSIS = "sandbox_analysis"
AI_SCORING = "ai_scoring"
REPORT_GENERATION = "report_generation"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
```

### RiskLevel Enum
```python
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"
UNKNOWN = "UNKNOWN"
```

### FileInfo Schema
```python
{
  "file_id": "string",
  "file_name": "string",
  "file_path": "string",
  "file_size": integer,
  "file_type": "string",
  "sha256": "string",
  "md5": "string",
  "upload_timestamp": float,
  "uploaded_by": "string (optional)",
  "metadata": {}
}
```

See `orchestrator/schemas.py` for complete schema definitions.

---

## Integration Points

### Backend Developer

**Your responsibilities:**
1. Implement the REST API endpoints listed above
2. Store file metadata in PostgreSQL
3. Store analysis results in PostgreSQL
4. Generate and store PDF reports
5. Provide job status endpoints for Frontend polling

**Key integration files:**
- Use schemas from `orchestrator/schemas.py` for data structures
- Orchestrator will call your endpoints at:
  - `PUT /api/jobs/{job_id}/status` - Job status updates
  - `PUT /api/jobs/{job_id}/result` - Final results
- Listen for job creation events from Orchestrator

**Example Spring Boot Controller:**
```java
@RestController
@RequestMapping("/api/jobs")
public class JobController {
    
    @PutMapping("/{jobId}/status")
    public ResponseEntity<?> updateJobStatus(
            @PathVariable String jobId,
            @RequestBody JobStatusUpdate update) {
        // Update job status in database
        // Notify frontend via WebSocket if needed
        return ResponseEntity.ok().build();
    }
    
    @PutMapping("/{jobId}/result")
    public ResponseEntity<?> updateJobResult(
            @PathVariable String jobId,
            @RequestBody AnalysisResult result) {
        // Store final results
        // Generate PDF report
        // Update database
        return ResponseEntity.ok().build();
    }
}
```

### Frontend Developer

**Your responsibilities:**
1. Upload files to Backend API
2. Poll job status endpoint
3. Display real-time analysis progress
4. Show final analysis results with visualizations
5. Download PDF reports

**API Usage:**
```javascript
// Upload file
const formData = new FormData();
formData.append('file', file);

const uploadResponse = await fetch('/api/files/upload', {
  method: 'POST',
  body: formData
});

const { job_id } = await uploadResponse.json();

// Poll job status
const pollJobStatus = async (jobId) => {
  const response = await fetch(`/api/jobs/${jobId}/status`);
  const status = await response.json();
  
  // Update UI with progress
  updateProgressBar(status.progress_percentage);
  updateStatusText(status.current_step);
  
  if (status.state === 'completed') {
    // Fetch final results
    const resultResponse = await fetch(`/api/jobs/${jobId}/result`);
    const results = await resultResponse.json();
    displayResults(results);
  }
};

// Poll every 2 seconds
setInterval(() => pollJobStatus(job_id), 2000);
```

### AI Engineer

**Your responsibilities:**
1. Implement `/score` endpoint that accepts the request schema above
2. Implement `/health` endpoint
3. Train ML models on sandbox results
4. Return structured risk scores with explanations

**Expected request format:**
- See "AI Service API Endpoints" section above

**Response format:**
- `ai_score`: Integer 0-100
- `confidence`: Float 0.0-1.0
- `explanation`: Array of strings
- `feature_importance`: Object with feature names and importance scores

**Example Flask endpoint:**
```python
@app.route('/score', methods=['POST'])
def calculate_score():
    data = request.json
    static_analysis = data['static_analysis']
    sandbox_analysis = data['sandbox_analysis']
    file_info = data['file_info']
    
    # Extract features
    features = extract_features(static_analysis, sandbox_analysis)
    
    # Predict
    score, confidence = model.predict(features)
    explanation = model.explain(features)
    
    return jsonify({
        'ai_score': int(score * 100),
        'confidence': float(confidence),
        'explanation': explanation,
        'feature_importance': model.get_feature_importance(),
        'model_version': 'v1.2.0'
    })
```

---

## Environment Configuration

All configuration is done via environment variables. See `orchestrator/config.py` for all available options.

### Required Environment Variables

#### Orchestrator
```bash
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=  # Optional
LOG_LEVEL=INFO
LOG_FILE=/var/log/zorbox/orchestrator.log
```

#### Backend Integration
```bash
BACKEND_API_URL=http://backend:8080
BACKEND_API_KEY=  # Optional, for authentication
BACKEND_API_TIMEOUT=30
BACKEND_RETRY_ATTEMPTS=3
```

#### AI Service Integration
```bash
AI_SERVICE_URL=http://ai-service:5000
AI_SERVICE_TIMEOUT=60
AI_SERVICE_RETRY_ATTEMPTS=3
```

#### Sandbox Configuration
```bash
STRELKA_ENABLED=true
NATIVE_ENGINE_ENABLED=true
CUCKOO_ENABLED=false  # Resource intensive
CAPE_ENABLED=false

STRELKA_TIMEOUT=60
NATIVE_ENGINE_TIMEOUT=120
CUCKOO_TIMEOUT=600
CAPE_TIMEOUT=600
```

---

## Error Handling

### Orchestrator Error Handling

The orchestrator implements comprehensive error handling:
- **Redis connection errors**: Automatic retry with exponential backoff
- **Backend API errors**: Retry up to 3 times, then mark job as failed
- **Sandbox analysis errors**: Continue with other sandboxes, log error
- **AI service errors**: Fallback to rule-based scoring, log error

### Error Response Format

When errors occur, jobs are marked as `FAILED` with:
```json
{
  "job_id": "job_123",
  "state": "failed",
  "error_message": "Detailed error description",
  "progress_percentage": 45
}
```

---

## Testing Guidelines

### Integration Testing

1. **Test Backend API endpoints**:
   ```bash
   curl -X PUT http://backend:8080/api/jobs/test-job/status \
     -H "Content-Type: application/json" \
     -d '{"job_id":"test-job","state":"static_analysis","progress_percentage":25}'
   ```

2. **Test AI Service**:
   ```bash
   curl -X POST http://ai-service:5000/score \
     -H "Content-Type: application/json" \
     -d @test_data.json
   ```

3. **Test Orchestrator health**:
   ```python
   from orchestrator import Orchestrator
   orch = Orchestrator()
   health = orch.health_check()
   print(health)  # {'redis': True, 'backend': True, 'ai_service': True}
   ```

---

## Next Steps

1. **Backend Developer**: Implement the REST API endpoints
2. **Frontend Developer**: Implement file upload and status polling
3. **AI Engineer**: Implement the `/score` endpoint
4. **Solution Architect**: Review and test integration points

---

## Questions?

Contact the Solution Architect for clarification on integration points.
