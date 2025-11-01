#!/usr/bin/env python3
import requests
import json

class CAPEClient:
    def __init__(self, api_url='http://cape:8000'):
        self.api_url = api_url
    
    def submit_file(self, file_path):
        """
        Faylı CAPE-ə göndər
        """
        url = f"{self.api_url}/api/tasks/create/file/"
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            response = requests.post(url, files=files)
            
            if response.status_code == 200:
                return response
                return response.json().get('task_id')
            else:
                raise Exception(f"CAPE submission failed: {response.text}")
    
    def get_report(self, task_id):
        """
        CAPE report-u al
        """
        url = f"{self.api_url}/api/tasks/get/report/{task_id}"
        response = requests.get(url)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to get CAPE report: {response.status_code}")
    
    def parse_report(self, report):
        """
        CAPE report-u parse et
        """
        summary = {
            'malscore': report.get('malscore', 0),
            'detections': report.get('detections', []),
            'signatures': [],
            'extracted_config': None,
            'shellcode': [],
            'memory_dumps': []
        }
        
        # Signatures
        for sig in report.get('signatures', []):
            summary['signatures'].append({
                'name': sig.get('name'),
                'severity': sig.get('severity'),
                'description': sig.get('description')
            })
        
        # Extracted malware config (CAPE özəlliyi)
        if 'CAPE' in report:
            summary['extracted_config'] = report['CAPE']
        
        # Shellcode detection
        if 'shellcode' in report:
            summary['shellcode'] = report['shellcode']
        
        return summary