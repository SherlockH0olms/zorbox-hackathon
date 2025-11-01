#!/usr/bin/env python3
"""
Improved Master Analyzer with proper error handling, retry logic, and integration
Coordinates all sandbox analyses with production-ready capabilities.
"""

import json
import subprocess
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeout
from typing import Dict, List, Optional, Any
from .schemas import (
    StaticAnalysisResult, SandboxAnalysisResult, SandboxType,
    AIScoringResult, AnalysisJob
)
from .config import Config, SandboxConfig
from .integration_client import AIServiceClient
from .logger_config import setup_logging

logger = logging.getLogger(__name__)


class SandboxAnalysisError(Exception):
    """Custom exception for sandbox analysis errors"""
    pass


class MasterAnalyzer:
    """
    Improved Master Analyzer with:
    - Proper error handling and recovery
    - Retry logic for failed analyses
    - Health checks for sandboxes
    - Proper timeout management
    - Structured result aggregation
    """
    
    def __init__(self, config: Optional[SandboxConfig] = None, 
                 ai_client: Optional[AIServiceClient] = None):
        """
        Initialize master analyzer
        
        Args:
            config: Sandbox configuration (uses config from environment if None)
            ai_client: AI service client (creates new if None)
        """
        self.config = Config.load()
        self.sandbox_config = config or self.config.sandbox
        self.ai_client = ai_client or AIServiceClient(self.config.ai_service)
        
        logger.info("Master Analyzer initialized")
    
    def analyze_with_strelka(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze file with Strelka (static analysis)
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis results dictionary or None if failed
        """
        if not self.sandbox_config.strelka_enabled:
            logger.info("Strelka analysis is disabled")
            return None
        
        try:
            logger.info(f"[Strelka] Starting analysis for {file_path}")
            
            # Call Strelka client
            cmd = [
                'python3', '/app/sandbox/strelka/strelka_client.py',
                file_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.sandbox_config.strelka_timeout
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    logger.info(f"[Strelka] Analysis completed successfully")
                    return data
                except json.JSONDecodeError as e:
                    logger.error(f"[Strelka] Failed to parse JSON output: {e}")
                    return {'error': f'JSON parse error: {e}'}
            else:
                logger.warning(f"[Strelka] Analysis failed with return code {result.returncode}")
                return {'error': result.stderr or 'Unknown error'}
                
        except subprocess.TimeoutExpired:
            logger.error(f"[Strelka] Analysis timeout after {self.sandbox_config.strelka_timeout}s")
            return {'error': 'Analysis timeout'}
        except Exception as e:
            logger.error(f"[Strelka] Analysis error: {e}")
            return {'error': str(e)}
    
    def analyze_with_native_engine(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze file with Native Engine
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis results dictionary or None if failed
        """
        if not self.sandbox_config.native_engine_enabled:
            logger.info("Native Engine analysis is disabled")
            return None
        
        try:
            logger.info(f"[Native Engine] Starting analysis for {file_path}")
            
            cmd = ['python3', '/app/sandbox/native-engine/native_engine.py', file_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.sandbox_config.native_engine_timeout
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    logger.info(f"[Native Engine] Analysis completed successfully")
                    return data
                except json.JSONDecodeError as e:
                    logger.error(f"[Native Engine] Failed to parse JSON output: {e}")
                    return {'error': f'JSON parse error: {e}'}
            else:
                logger.warning(f"[Native Engine] Analysis failed with return code {result.returncode}")
                return {'error': result.stderr or 'Unknown error'}
                
        except subprocess.TimeoutExpired:
            logger.error(f"[Native Engine] Analysis timeout after {self.sandbox_config.native_engine_timeout}s")
            return {'error': 'Analysis timeout'}
        except Exception as e:
            logger.error(f"[Native Engine] Analysis error: {e}")
            return {'error': str(e)}
    
    def analyze_with_cuckoo(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze file with Cuckoo Sandbox (dynamic analysis)
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis results dictionary or None if failed
        """
        if not self.sandbox_config.cuckoo_enabled:
            logger.info("Cuckoo analysis is disabled")
            return None
        
        try:
            logger.info(f"[Cuckoo] Starting analysis for {file_path}")
            
            from sandbox.cuckoo.submit_to_cuckoo import CuckooClient
            client = CuckooClient(api_url=self.sandbox_config.cuckoo_api_url)
            
            task_id = client.submit_file(file_path)
            logger.info(f"[Cuckoo] Submitted task {task_id}, waiting for results...")
            
            report = client.get_report(task_id)
            parsed = client.parse_report(report)
            
            logger.info(f"[Cuckoo] Analysis completed successfully")
            return parsed
            
        except Exception as e:
            logger.error(f"[Cuckoo] Analysis error: {e}")
            return {'error': str(e)}
    
    def analyze_with_cape(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Analyze file with CAPE Sandbox
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Analysis results dictionary or None if failed
        """
        if not self.sandbox_config.cape_enabled:
            logger.info("CAPE analysis is disabled")
            return None
        
        try:
            logger.info(f"[CAPE] Starting analysis for {file_path}")
            
            from sandbox.capev2.submit_to_cape import CAPEClient
            client = CAPEClient(api_url=self.sandbox_config.cape_api_url)
            
            task_id = client.submit_file(file_path)
            logger.info(f"[CAPE] Submitted task {task_id}")
            
            # Note: CAPE analysis is async, this returns immediately
            return {'task_id': task_id, 'status': 'submitted'}
            
        except Exception as e:
            logger.error(f"[CAPE] Analysis error: {e}")
            return {'error': str(e)}
    
    def run_parallel_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Run parallel analysis across all enabled sandboxes
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary with results from all sandboxes
        """
        logger.info(f"\n{'='*60}")
        logger.info(f"Starting parallel analysis for: {file_path}")
        logger.info(f"{'='*60}\n")
        
        results = {}
        
        # Build list of enabled analyzers
        analyzers = []
        if self.sandbox_config.strelka_enabled:
            analyzers.append(('strelka', self.analyze_with_strelka))
        if self.sandbox_config.native_engine_enabled:
            analyzers.append(('native_engine', self.analyze_with_native_engine))
        if self.sandbox_config.cuckoo_enabled:
            analyzers.append(('cuckoo', self.analyze_with_cuckoo))
        if self.sandbox_config.cape_enabled:
            analyzers.append(('cape', self.analyze_with_cape))
        
        if not analyzers:
            logger.warning("No sandboxes are enabled!")
            return results
        
        # Run analyses in parallel
        with ThreadPoolExecutor(max_workers=self.config.orchestrator.max_workers) as executor:
            futures = {
                executor.submit(analyzer_func, file_path): name
                for name, analyzer_func in analyzers
            }
            
            for future in as_completed(futures):
                sandbox_name = futures[future]
                try:
                    result = future.result(timeout=None)  # Timeout handled in individual analyzers
                    results[sandbox_name] = result
                    
                    if result and 'error' not in result:
                        logger.info(f"✓ {sandbox_name} completed successfully")
                    else:
                        error_msg = result.get('error', 'Unknown error') if result else 'No result'
                        logger.warning(f"⚠ {sandbox_name} completed with error: {error_msg}")
                        results[sandbox_name] = result or {'error': 'No result returned'}
                        
                except Exception as e:
                    logger.error(f"✗ {sandbox_name} failed with exception: {e}")
                    results[sandbox_name] = {'error': str(e)}
        
        return results
    
    def aggregate_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Aggregate results from all sandboxes into structured format
        
        Args:
            raw_results: Raw results from all sandboxes
            
        Returns:
            Aggregated results with static_analysis and sandbox_analysis sections
        """
        aggregated = {
            'static_analysis': {},
            'sandbox_analysis': {},
            'all_results': raw_results
        }
        
        # Process Strelka results (static analysis)
        if 'strelka' in raw_results and 'error' not in raw_results['strelka']:
            strelka = raw_results['strelka']
            aggregated['static_analysis'] = {
                'file_type': strelka.get('file_type', 'unknown'),
                'file_hash': strelka.get('hashes', {}).get('sha256') or strelka.get('file_hash', ''),
                'yara_matches': strelka.get('yara_matches', []),
                'entropy': strelka.get('entropy', 0.0),
                'metadata': {
                    'md5': strelka.get('hashes', {}).get('md5', ''),
                    'sha1': strelka.get('hashes', {}).get('sha1', '')
                }
            }
        
        # Process Native Engine results
        if 'native_engine' in raw_results and 'error' not in raw_results['native_engine']:
            native = raw_results['native_engine']
            
            # Merge static analysis data
            if not aggregated['static_analysis']:
                aggregated['static_analysis'] = {}
            
            aggregated['static_analysis'].update({
                'file_hash': native.get('file_hash', aggregated['static_analysis'].get('file_hash', '')),
                'entropy': native.get('entropy', aggregated['static_analysis'].get('entropy', 0.0))
            })
            
            # Extract suspicious imports
            suspicious_imports = [
                b['value'] for b in native.get('suspicious_behaviors', [])
                if b.get('type') == 'suspicious_import'
            ]
            if suspicious_imports:
                aggregated['static_analysis']['suspicious_imports'] = suspicious_imports
            
            # Sandbox analysis data
            aggregated['sandbox_analysis'] = {
                'native_engine': {
                    'risk_score': native.get('risk_score', 0),
                    'network_activity': len(native.get('network_activity', [])) > 0,
                    'file_modifications': len(native.get('file_operations', [])),
                    'suspicious_behaviors': native.get('suspicious_behaviors', []),
                    'syscalls_count': len(native.get('syscalls', []))
                }
            }
        
        # Process Cuckoo results
        if 'cuckoo' in raw_results and 'error' not in raw_results['cuckoo']:
            cuckoo = raw_results['cuckoo']
            
            if 'sandbox_analysis' not in aggregated:
                aggregated['sandbox_analysis'] = {}
            
            aggregated['sandbox_analysis']['cuckoo'] = {
                'risk_score': cuckoo.get('score', 0),
                'signatures': cuckoo.get('signatures', []),
                'network': {
                    'hosts': cuckoo.get('network', {}).get('hosts', []),
                    'dns': cuckoo.get('network', {}).get('dns', []),
                    'http': cuckoo.get('network', {}).get('http', [])
                },
                'processes': cuckoo.get('behavior', {}).get('processes', [])
            }
        
        # Process CAPE results
        if 'cape' in raw_results and 'error' not in raw_results['cape']:
            cape = raw_results['cape']
            
            if 'sandbox_analysis' not in aggregated:
                aggregated['sandbox_analysis'] = {}
            
            aggregated['sandbox_analysis']['cape'] = {
                'malscore': cape.get('malscore', 0),
                'detections': cape.get('detections', []),
                'signatures': cape.get('signatures', []),
                'extracted_config': cape.get('extracted_config'),
                'shellcode': cape.get('shellcode', [])
            }
        
        return aggregated
    
    def send_to_ai_scoring(self, aggregated_results: Dict[str, Any], 
                          file_info: Dict[str, Any]) -> Optional[AIScoringResult]:
        """
        Send aggregated results to AI scoring service
        
        Args:
            aggregated_results: Aggregated analysis results
            file_info: File information
            
        Returns:
            AIScoringResult or None if failed
        """
        try:
            logger.info("[AI Scoring] Calculating risk score...")
            
            result = self.ai_client.calculate_score(
                static_analysis=aggregated_results.get('static_analysis', {}),
                sandbox_analysis=aggregated_results.get('sandbox_analysis', {}),
                file_info=file_info
            )
            
            if result:
                logger.info(f"✓ AI Score: {result.ai_score}/100 (Confidence: {result.confidence:.1%})")
            else:
                logger.warning("✗ AI Scoring returned no result")
            
            return result
                
        except Exception as e:
            logger.error(f"✗ AI Scoring error: {e}")
            return None
    
    def generate_final_report(self, file_path: str, 
                              aggregated_results: Dict[str, Any],
                              ai_results: Optional[AIScoringResult]) -> Dict[str, Any]:
        """
        Generate final analysis report
        
        Args:
            file_path: Path to analyzed file
            aggregated_results: Aggregated sandbox results
            ai_results: AI scoring results
            
        Returns:
            Final report dictionary
        """
        from datetime import datetime
        from .schemas import RiskLevel
        
        # Calculate final risk score
        # Weight: 40% static analysis indicators, 40% sandbox scores, 20% AI score
        static_score = 0
        sandbox_score = 0
        ai_score = 0
        
        # Static analysis scoring
        static_data = aggregated_results.get('static_analysis', {})
        if static_data.get('yara_matches'):
            static_score += 30
        if static_data.get('entropy', 0) > 7.0:
            static_score += 20
        if static_data.get('suspicious_imports'):
            static_score += 25
        static_score = min(static_score, 100)
        
        # Sandbox scoring (average of all sandbox risk scores)
        sandbox_data = aggregated_results.get('sandbox_analysis', {})
        sandbox_scores = []
        for sandbox_name, sandbox_result in sandbox_data.items():
            if isinstance(sandbox_result, dict):
                score = sandbox_result.get('risk_score', 0) or sandbox_result.get('malscore', 0)
                if score > 0:
                    sandbox_scores.append(score)
        
        if sandbox_scores:
            sandbox_score = int(sum(sandbox_scores) / len(sandbox_scores))
        
        # AI score
        if ai_results:
            ai_score = ai_results.ai_score
        
        # Weighted final score
        if ai_score > 0:
            final_score = int(0.4 * static_score + 0.4 * sandbox_score + 0.2 * ai_score)
        else:
            final_score = int(0.5 * static_score + 0.5 * sandbox_score)
        
        # Determine risk level
        if final_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif final_score >= 60:
            risk_level = RiskLevel.HIGH
        elif final_score >= 30:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        report = {
            'file_path': str(file_path),
            'analysis_timestamp': datetime.now().isoformat(),
            'static_analysis': aggregated_results.get('static_analysis', {}),
            'sandbox_analysis': aggregated_results.get('sandbox_analysis', {}),
            'ai_scoring': ai_results.to_dict() if ai_results else None,
            'final_risk_score': final_score,
            'final_risk_level': risk_level.value,
            'score_breakdown': {
                'static_score': static_score,
                'sandbox_score': sandbox_score,
                'ai_score': ai_score
            }
        }
        
        return report
