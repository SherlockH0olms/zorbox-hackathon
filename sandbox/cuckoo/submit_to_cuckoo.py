#!/usr/bin/env python3
import requests
import json
import time

class CuckooClient:
    def __init__(self, api_url='http://cuckoo-api:8090'):
        self.api_url = api_url
    
    def submit_file(self, file_path, options=None):
        """
        Faylı Cuckoo-ya göndər
        """
        url = f"{self.api_url}/tasks/create/file"
        
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = options or {}
            
            response = requests.post(url, files=files, data=data)
            result = response.json()
            
            if result.get('task_id'):
                return result['task_id']
            else:
                raise Exception(f"Cuckoo submission failed: {result}")
    
    def get_report(self, task_id):
        """
        Analiz nəticəsini al
        """
        url = f"{self.api_url}/tasks/report/{task_id}"
        
        # completition
        max_wait = 300  # 5 dq
        waited = 0
        
        while waited < max_wait:
            response = requests.get(url)
            
            if response.status_code == 200:
                return response.json()
            
            time.sleep(10)
            waited += 10
        
        raise Exception("Cuckoo analysis timeout")
    
    def parse_report(self, report):
        """
        Cuckoo report-u sadələşdir
        """
        summary = {
            'score': report.get('info', {}).get('score', 0),
            'signatures': [],
            'network': {
                'hosts': [],
                'dns': [],
                'http': []
            },
            'behavior': {
                'processes': [],
                'files': []
            }
        }
        
        # imzaalr
        for sig in report.get('signatures', []):
            summary['signatures'].append({
                'name': sig.get('name'),
                'severity': sig.get('severity'),
                'description': sig.get('description')
            })
        
        # Network
        network_data = report.get('network', {})
        summary['network']['hosts'] = network_data.get('hosts', [])
        summary['network']['dns'] = network_data.get('dns', [])
        
        # Behavor
        behavior_data = report.get('behavior', {})
        if 'processes' in behavior_data:
            for proc in behavior_data['processes'][:10]:  # İlk 10
                summary['behavior']['processes'].append({
                    'name': proc.get('process_name'),
                    'pid': proc.get('process_id')
                })
        
        return summary