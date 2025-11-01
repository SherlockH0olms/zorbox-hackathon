#!/usr/bin/env python3
import os
import subprocess
import json
import hashlib
import pefile
import time
from pathlib import Path

class NativeEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        self.results = {
            "file_hash": "",
            "syscalls": [],
            "network_activity": [],
            "file_operations": [],
            "suspicious_behaviors": [],
            "risk_score": 0
        }
    
    def calculate_hash(self):
        """Fayl hash-ini hesablas;m"""
        with open(self.file_path, 'rb') as f:
            self.results["file_hash"] = hashlib.sha256(f.read()).hexdigest()
    
    def analyze_pe(self):
        """PE fayl strukturunu analiz etsin"""
        try:
            pe = pefile.PE(self.file_path)
            
            # Suspicious imports yoxla
            suspicious_apis = [
                'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                'LoadLibrary', 'GetProcAddress', 'ShellExecute', 'WinExec'
            ]
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode() in suspicious_apis:
                            self.results["suspicious_behaviors"].append({
                                "type": "suspicious_import",
                                "value": imp.name.decode(),
                                "severity": "high"
                            })
                            self.results["risk_score"] += 15
            
            # Entropy yoxla yenipacked fayllar
            for section in pe.sections:
                entropy = section.get_entropy()
                if entropy > 7.0:  # entropy burda verdim
                    self.results["suspicious_behaviors"].append({
                        "type": "high_entropy",
                        "section": section.Name.decode().strip('\x00'),
                        "entropy": entropy,
                        "severity": "medium"
                    })
                    self.results["risk_score"] += 10
                    
        except Exception as e:
            print(f"PE analysis error: {e}")
    
    def run_strace(self):
        """Firejail və strace ilə isolated icra"""
        try:
            # Firejail ilə isolated environmentdə işə sal
            cmd = [
                'firejail',
                '--noprofile',
                '--net=none',  
                '--private',
                '--timeout=00:02:00',  
                'strace',
                '-f',
                '-e', 'trace=network,file,process',
                '-o', '/tmp/strace.log',
                self.file_path
            ]
            
            subprocess.run(cmd, timeout=120, capture_output=True)
            
            # log
            if os.path.exists('/tmp/strace.log'):
                with open('/tmp/strace.log', 'r') as f:
                    lines = f.readlines()
                    self.results["syscalls"] = lines[:100]  # 100 sətr
                    
                    # pislerisyscalls yoxla
                    for line in lines:
                        if 'connect(' in line or 'socket(' in line:
                            self.results["network_activity"].append(line.strip())
                            self.results["risk_score"] += 5
                        if 'open(' in line and '/etc/passwd' in line:
                            self.results["suspicious_behaviors"].append({
                                "type": "sensitive_file_access",
                                "value": line.strip(),
                                "severity": "critical"
                            })
                            self.results["risk_score"] += 30
                            
        except Exception as e:
            print(f"Strace analysis error: {e}")
    
    def generate_report(self):
        """Final hesabat yarat"""
        # skor
        if self.results["risk_score"] >= 80:
            risk_level = "CRITICAL"
        elif self.results["risk_score"] >= 60:
            risk_level = "HIGH"
        elif self.results["risk_score"] >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        self.results["risk_level"] = risk_level
        return self.results

def analyze_file(file_path):
    """Main analiz funksiyası"""
    engine = NativeEngine(file_path)
    
    # Hash 
    engine.calculate_hash()
    
    # PE fayl analizə
    if file_path.endswith('.exe') or file_path.endswith('.dll'):
        engine.analyze_pe()
    
    # Dynamic analiz (isolated)
    # engine.run_strace()  # MVP catsdirsak
    
    return engine.generate_report()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = analyze_file(sys.argv[1])
        print(json.dumps(result, indent=2))