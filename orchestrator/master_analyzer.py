#!/usr/bin/env python3
"""
Master analyzer - Bütün sandbox-ları koordinasiya edir
"""
import sys
sys.path.append('/app/sandbox/cuckoo')
sys.path.append('/app/sandbox/capev2')
sys.path.append('/app/sandbox/strelka')
sys.path.append('/app/sandbox/native-engine')

import json
import subprocess
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

class MasterAnalyzer:
    def __init__(self):
        self.results = {}
    
    def analyze_with_strelka(self, file_path):
        """
        Strelka ilə statik analiz
        """
        try:
            print(f"[Strelka] Analyzing {file_path}...")
            
            # Strelka client çağır;r;q burda
            cmd = [
                'python3', '/app/sandbox/strelka/strelka_client.py',
                file_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {'error': result.stderr}
                
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_with_native_engine(self, file_path):
        """
        Native Engine ilə analiz
        """
        try:
            print(f"[Native Engine] Analyzing {file_path}...")
            
            cmd = ['python3', '/app/sandbox/native-engine/native_engine.py', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {'error': result.stderr}
                
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_with_cuckoo(self, file_path):
        """
        Cuckoo Sandbox ilə dinamik analiz
        """
        try:
            print(f"[Cuckoo] Analyzing {file_path}...")
            
            from submit_to_cuckoo import CuckooClient
            client = CuckooClient()
            
            task_id = client.submit_file(file_path)
            report = client.get_report(task_id)
            parsed = client.parse_report(report)
            
            return parsed
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_with_cape(self, file_path):
        """
        CAPE Sandbox ilə analiz
        """
        try:
            print(f"[CAPE] Analyzing {file_path}...")
            
            from submit_to_cape import CAPEClient
            client = CAPEClient()
            
            task_id = client.submit_file(file_path)
            # async qaytar
            return {'task_id': task_id, 'status': 'submitted'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def run_parallel_analysis(self, file_path):
        """
        Bütün sandbox-ları paralel işə sal
        """
        print(f"\n{'='*60}")
        print(f"Starting parallel analysis for: {file_path}")
        print(f"{'='*60}\n")
        
        # ThreadPoolExecutor ilə paralel işə sal
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.analyze_with_strelka, file_path): 'strelka',
                executor.submit(self.analyze_with_native_engine, file_path): 'native_engine',
                executor.submit(self.analyze_with_cuckoo, file_path): 'cuckoo',
                # CAPE
                # executor.submit(self.analyze_with_cape, file_path): 'cape'
            }
            
            for future in as_completed(futures):
                sandbox_name = futures[future]
                try:
                    result = future.result()
                    self.results[sandbox_name] = result
                    print(f"✓ {sandbox_name} completed")
                except Exception as e:
                    self.results[sandbox_name] = {'error': str(e)}
                    print(f"✗ {sandbox_name} failed: {e}")
        
        return self.results
    
    def aggregate_results(self):
        """
        Bütün sandbox nəticələrini birləşdir
        """
        aggregated = {
            'static_analysis': {},
            'sandbox_analysis': {},
            'all_results': self.results
        }
        
        # Strelka nəticələri (static)
        if 'strelka' in self.results and 'error' not in self.results['strelka']:
            strelka = self.results['strelka']
            aggregated['static_analysis'] = {
                'file_type': strelka.get('file_type'),
                'yara_matches': strelka.get('yara_matches', []),
                'entropy': strelka.get('entropy', 0),
                'hashes': strelka.get('hashes', {})
            }
        
        # Native Engine nəticelei
        if 'native_engine' in self.results and 'error' not in self.results['native_engine']:
            native = self.results['native_engine']
            aggregated['static_analysis'].update({
                'imports': [b['value'] for b in native.get('suspicious_behaviors', []) 
                           if b['type'] == 'suspicious_import'],
                'entropy': native.get('entropy', aggregated['static_analysis'].get('entropy', 0))
            })
            
            aggregated['sandbox_analysis'] = {
                'network_activity': len(native.get('network_activity', [])) > 0,
                'file_modifications': len(native.get('file_operations', [])),
                'risk_score': native.get('risk_score', 0),
                'suspicious_behaviors': native.get('suspicious_behaviors', [])
            }
        
        # Cuckoo nəticelei
        if 'cuckoo' in self.results and 'error' not in self.results['cuckoo']:
            cuckoo = self.results['cuckoo']
            aggregated['sandbox_analysis'].update({
                'cuckoo_score': cuckoo.get('score', 0),
                'signatures': cuckoo.get('signatures', []),
                'network': cuckoo.get('network', {}),
                'processes': cuckoo.get('behavior', {}).get('processes', [])
            })
        
        return aggregated
    
    def send_to_ai_scoring(self, aggregated_results):
        """
        Nəticələri AI scoring service-ə göndər
        """
        try:
            print("\n[AI Scoring] Calculating risk score...")
            
            response = requests.post(
                'http://ai-service:5000/score',
                json=aggregated_results,
                timeout=30
            )
            
            if response.status_code == 200:
                ai_result = response.json()
                print(f"✓ AI Score: {ai_result.get('ai_score')}/100")
                return ai_result
            else:
                print(f"✗ AI Scoring failed: {response.status_code}")
                return {'error': 'AI scoring failed'}
                
        except Exception as e:
            print(f"✗ AI Scoring error: {e}")
            return {'error': str(e)}
    
    def generate_final_report(self, file_path, aggregated_results, ai_results):
        """
        Final hesabat yarat
        """
        report = {
            'file_path': str(file_path),
            'analysis_timestamp': None,  # datetime.now().isoformat()
            'static_analysis': aggregated_results.get('static_analysis', {}),
            'sandbox_analysis': aggregated_results.get('sandbox_analysis', {}),
            'ai_scoring': ai_results,
            'final_risk_score': 0,
            'final_risk_level': 'UNKNOWN'
        }
        
        # Final risk calcul
        ai_score = ai_results.get('ai_score', 0)
        sandbox_score = aggregated_results.get('sandbox_analysis', {}).get('risk_score', 0)
        
        # Weighted avger 60% rule-based (sandbox), 40% AI
        final_score = int(0.6 * sandbox_score + 0.4 * ai_score)
        report['final_risk_score'] = final_score
        
        # Risk level
        if final_score >= 80:
            report['final_risk_level'] = 'CRITICAL'
        elif final_score >= 60:
            report['final_risk_level'] = 'HIGH'
        elif final_score >= 30:
            report['final_risk_level'] = 'MEDIUM'
        else:
            report['final_risk_level'] = 'LOW'
        
        return report

def main():
    """
    Test analyzer
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python master_analyzer.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    if not Path(file_path).exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Master analyzer
    analyzer = MasterAnalyzer()
    
    # Parallel analiz
    results = analyzer.run_parallel_analysis(file_path)
    
    # Aggregate
    aggregated = analyzer.aggregate_results()
    
    # AI scoring
    ai_results = analyzer.send_to_ai_scoring(aggregated)
    
    # Final report
    final_report = analyzer.generate_final_report(file_path, aggregated, ai_results)
    
    # Output
    print("\n" + "="*60)
    print("FINAL ANALYSIS REPORT")
    print("="*60)
    print(json.dumps(final_report, indent=2))
    
    # Save to file
    output_file = f"/tmp/analysis_report_{Path(file_path).stem}.json"
    with open(output_file, 'w') as f:
        json.dumps(final_report, f, indent=2)
    print(f"\nReport saved to: {output_file}")

if __name__ == "__main__":
    main()