#!/usr/bin/env python3
"""
ZORBOX Native Engine - Advanced Malware Analysis
Version: 2.1 PRODUCTION READY with API Server
Author: Solution Architect Team + Your Code

REAL MALWARE DETECTION:
- Process Injection Detection
- Anti-Debug/Anti-VM Detection
- Packer Detection (UPX, ASPack, Themida)
- Memory Analysis
- YARA Rules Integration
- Behavioral Analysis (strace monitoring)
- IOC Extraction
- API Server Integration (Orchestrator compatible)
"""

import os
import sys
import json
import hashlib
import subprocess
import re
import math
import struct
import time
import logging
import argparse
from pathlib import Path
from collections import defaultdict
import tempfile
import shutil
from datetime import datetime
import threading
import redis

try:
    import pefile
    import yara
    from capstone import *
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError as e:
    print(f"[!] Missing dependencies: {e}")
    print("[!] Install: pip3 install pefile yara-python capstone flask flask-cors redis")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/native_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AdvancedNativeEngine:
    """
    Production-ready malware analysis engine
    """
    
    def __init__(self, file_path, timeout=120, task_id=None, redis_client=None):
        self.file_path = Path(file_path)
        self.timeout = timeout
        self.task_id = task_id or str(int(time.time()))
        self.redis_client = redis_client
        
        self.results = {
            "task_id": self.task_id,
            "timestamp": datetime.now().isoformat(),
            "file_path": str(file_path),
            "metadata": {},
            "static_analysis": {},
            "behavioral_analysis": {},
            "memory_analysis": {},
            "anti_detection": {},
            "yara_matches": [],
            "network_indicators": {},
            "risk_scoring": {
                "total_score": 0,
                "severity": "UNKNOWN",
                "confidence": 0.0,
                "detection_reasons": []
            },
            "iocs": []
        }
        
        # Risk weights
        self.risk_weights = {
            "critical": 30,
            "high": 20,
            "medium": 10,
            "low": 5
        }
        
        # YARA rules path
        self.yara_rules_path = Path(__file__).parent / "yara_rules"
    
    def update_redis_status(self, status, progress=0):
        """Update task status in Redis"""
        if self.redis_client:
            try:
                key = f"task:{self.task_id}"
                self.redis_client.hset(key, mapping={
                    "status": status,
                    "progress": progress,
                    "updated_at": time.time()
                })
            except Exception as e:
                logger.warning(f"Redis update failed: {e}")
    
    def add_ioc(self, ioc_type, value, severity="medium", description=""):
        """Add IOC and increase risk score"""
        self.results["iocs"].append({
            "type": ioc_type,
            "value": value,
            "severity": severity,
            "description": description,
            "timestamp": time.time()
        })
        self.results["risk_scoring"]["total_score"] += self.risk_weights.get(severity, 5)
        self.results["risk_scoring"]["detection_reasons"].append(description)
    
    def calculate_entropy(self, data):
        """Shannon entropy calculation (packed/encrypted detection)"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    def analyze_metadata(self):
        """File metadata and hash analysis"""
        try:
            self.update_redis_status("analyzing_metadata", 10)
            
            stat = self.file_path.stat()
            
            with open(self.file_path, 'rb') as f:
                data = f.read()
                
            self.results["metadata"] = {
                "filename": self.file_path.name,
                "size": stat.st_size,
                "md5": hashlib.md5(data).hexdigest(),
                "sha1": hashlib.sha1(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "entropy": self.calculate_entropy(data),
                "magic_bytes": data[:16].hex()
            }
            
            # High entropy = packed/encrypted
            if self.results["metadata"]["entropy"] > 7.2:
                self.add_ioc(
                    "entropy",
                    f"High entropy: {self.results['metadata']['entropy']:.2f}",
                    "high",
                    "Possible packed or encrypted binary (entropy > 7.2)"
                )
            
            # Tiny file size but EXE
            if str(self.file_path).endswith('.exe') and stat.st_size < 10000:
                self.add_ioc(
                    "tiny_executable",
                    f"Unusually small EXE: {stat.st_size} bytes",
                    "medium",
                    "Dropper or launcher malware"
                )
                
            logger.info(f"Metadata analysis complete - SHA256: {self.results['metadata']['sha256']}")
                
        except Exception as e:
            logger.error(f"Metadata analysis error: {e}")
    
    def detect_packer(self, pe):
        """Detect common packers (UPX, ASPack, Themida, etc.)"""
        packer_signatures = {
            "UPX": [b"UPX0", b"UPX1", b"UPX2"],
            "ASPack": [b"ASPack", b".aspack", b".adata"],
            "PECompact": [b"PECompact", b".pec1", b".pec2"],
            "Themida": [b"Themida", b".themida"],
            "VMProtect": [b"VMProtect", b".vmp0", b".vmp1"],
            "Armadillo": [b"Armadillo", b".data"],
            "NSPack": [b"NSPack", b".nsp0"],
            "MEW": [b"MEW"],
            "FSG": [b"FSG!"],
            "Petite": [b"Petite", b".petite"]
        }
        
        detected_packers = []
        
        try:
            # Check section names
            for section in pe.sections:
                section_name = section.Name
                for packer, signatures in packer_signatures.items():
                    for sig in signatures:
                        if sig in section_name:
                            detected_packers.append(packer)
                            self.add_ioc(
                                "packer_detected",
                                packer,
                                "critical",
                                f"Packed with {packer} - obfuscation detected"
                            )
                            break
            
            # Check entry point section entropy
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    if section.get_entropy() > 7.0:
                        self.add_ioc(
                            "packed_entrypoint",
                            f"Entry point in high-entropy section: {section.Name.decode().strip()}",
                            "high",
                            "Entry point code is likely packed"
                        )
            
            if detected_packers:
                self.results["static_analysis"]["packer"] = list(set(detected_packers))
            
        except Exception as e:
            logger.error(f"Packer detection error: {e}")
    
    def analyze_pe_advanced(self):
        """Advanced PE analysis - real malware detection"""
        if not (str(self.file_path).endswith('.exe') or str(self.file_path).endswith('.dll')):
            return
        
        try:
            self.update_redis_status("pe_analysis", 20)
            
            pe = pefile.PE(str(self.file_path))
            
            analysis = {
                "is_dll": pe.is_dll(),
                "is_exe": pe.is_exe(),
                "is_driver": pe.is_driver(),
                "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
                "sections": [],
                "imports": defaultdict(list),
                "exports": [],
                "suspicious_imports": [],
                "resources": [],
                "digital_signature": None,
                "packer_detected": False,
                "anomalies": []
            }
            
            # Detect packers first
            self.detect_packer(pe)
            
            # 1. Section Analysis
            for section in pe.sections:
                section_name = section.Name.decode().strip('\x00')
                section_entropy = section.get_entropy()
                
                section_data = {
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section_entropy,
                    "characteristics": hex(section.Characteristics)
                }
                
                analysis["sections"].append(section_data)
                
                # High entropy = packer/encryption
                if section_entropy > 7.0:
                    analysis["packer_detected"] = True
                    self.add_ioc(
                        "packed_section",
                        f"Section {section_name} entropy: {section_entropy:.2f}",
                        "high",
                        "Packed or encrypted section detected"
                    )
                
                # Executable + Writable = shellcode injection vector
                if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                    self.add_ioc(
                        "suspicious_section",
                        f"Section {section_name} is Writable+Executable",
                        "critical",
                        "RWX section - code injection vector"
                    )
                
                # Raw size = 0 but virtual size > 0 (packed)
                if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
                    self.add_ioc(
                        "virtual_section",
                        f"Section {section_name} has no raw data",
                        "high",
                        "Virtual-only section (packed/runtime generated)"
                    )
            
            # 2. Import Analysis - Suspicious APIs
            suspicious_api_categories = {
                "process_injection": [
                    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                    "OpenProcess", "VirtualProtectEx", "SetThreadContext",
                    "ResumeThread", "QueueUserAPC", "NtUnmapViewOfSection",
                    "ZwUnmapViewOfSection", "RtlCreateUserThread"
                ],
                "persistence": [
                    "RegSetValueEx", "RegCreateKeyEx", "CreateServiceA",
                    "CreateServiceW", "SetWindowsHookEx", "WriteFile",
                    "CopyFile", "MoveFile"
                ],
                "keylogging": [
                    "GetAsyncKeyState", "GetKeyState", "SetWindowsHookEx",
                    "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW"
                ],
                "network": [
                    "InternetOpenA", "InternetOpenUrlA", "HttpOpenRequestA",
                    "WSAStartup", "socket", "connect", "send", "recv",
                    "InternetReadFile", "URLDownloadToFileA", "WinHttpOpen"
                ],
                "anti_analysis": [
                    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                    "NtQueryInformationProcess", "OutputDebugString",
                    "GetTickCount", "QueryPerformanceCounter", "NtSetInformationThread"
                ],
                "crypto": [
                    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
                    "CertOpenStore", "CryptCreateHash"
                ],
                "privilege_escalation": [
                    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue"
                ]
            }
            
            api_count_by_category = defaultdict(int)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode()
                            analysis["imports"][dll_name].append(api_name)
                            
                            # Check suspicious APIs
                            for category, apis in suspicious_api_categories.items():
                                if api_name in apis:
                                    api_count_by_category[category] += 1
                                    
                                    analysis["suspicious_imports"].append({
                                        "dll": dll_name,
                                        "api": api_name,
                                        "category": category
                                    })
                                    
                                    severity = "critical" if category in ["process_injection", "privilege_escalation"] else "high"
                                    self.add_ioc(
                                        "suspicious_import",
                                        f"{dll_name}!{api_name}",
                                        severity,
                                        f"Suspicious API: {category}"
                                    )
            
            # Multiple process injection APIs = definite malware
            if api_count_by_category["process_injection"] >= 3:
                self.add_ioc(
                    "process_injection_kit",
                    f"{api_count_by_category['process_injection']} injection APIs",
                    "critical",
                    "Complete process injection toolkit detected"
                )
            
            # 3. Export Analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        export_name = exp.name.decode()
                        analysis["exports"].append(export_name)
                        
                        # DLL exports with suspicious names
                        if any(susp in export_name.lower() for susp in ['inject', 'hook', 'bypass', 'dump']):
                            self.add_ioc(
                                "suspicious_export",
                                export_name,
                                "high",
                                "Suspicious export function name"
                            )
            
            # 4. Resource Analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                total_resource_size = 0
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    total_resource_size += size
                                    
                                    analysis["resources"].append({
                                        "type": resource_type.id,
                                        "size": size,
                                        "rva": hex(data_rva)
                                    })
                                    
                                    # Large resource = embedded payload
                                    if size > 100000:  # 100KB
                                        self.add_ioc(
                                            "large_resource",
                                            f"Large resource: {size} bytes",
                                            "medium",
                                            "Possible embedded payload or dropper"
                                        )
                
                # Total resources > 50% of file = suspicious
                if total_resource_size > (self.results["metadata"]["size"] * 0.5):
                    self.add_ioc(
                        "resource_heavy",
                        f"Resources: {total_resource_size}/{self.results['metadata']['size']} bytes",
                        "high",
                        "File is mostly resources (dropper pattern)"
                    )
            
            # 5. Digital Signature Check
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if security_dir.VirtualAddress == 0:
                analysis["digital_signature"] = "NOT_SIGNED"
                self.add_ioc(
                    "unsigned_binary",
                    "No digital signature",
                    "medium",
                    "Unsigned executable (common in malware)"
                )
            else:
                analysis["digital_signature"] = "SIGNED"
            
            # 6. Anomaly detection
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                self.add_ioc(
                    "tls_callback",
                    "TLS callback present",
                    "high",
                    "TLS callback - possible anti-debug technique"
                )
            
            # Entry point outside code section
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_in_code = False
            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    if section.Characteristics & 0x20000000:  # Executable
                        ep_in_code = True
            
            if not ep_in_code:
                self.add_ioc(
                    "abnormal_entrypoint",
                    f"Entry point at {hex(ep)} not in executable section",
                    "critical",
                    "Entry point in non-executable section (obfuscation)"
                )
            
            # 7. Anti-Debug/Anti-VM detection
            self.detect_anti_techniques(pe)
            
            self.results["static_analysis"]["pe"] = analysis
            
            pe.close()
            logger.info("PE analysis complete")
            
        except Exception as e:
            logger.error(f"PE analysis error: {e}")
    
    def detect_anti_techniques(self, pe):
        """Detect anti-debug and anti-VM techniques"""
        anti_patterns = {
            "IsDebuggerPresent": (rb"IsDebuggerPresent", "Anti-debug: IsDebuggerPresent check"),
            "CheckRemoteDebugger": (rb"CheckRemoteDebuggerPresent", "Anti-debug: Remote debugger check"),
            "NtQueryInformationProcess": (rb"NtQueryInformationProcess", "Anti-debug: Process information query"),
            "OutputDebugString": (rb"OutputDebugStringA", "Anti-debug: OutputDebugString trick"),
            "INT3_instruction": (rb"\xCC", "Anti-debug: INT 3 breakpoint"),
            "RDTSC_instruction": (rb"\x0F\x31", "Anti-debug: RDTSC timing check"),
            "VMware_string": (rb"VMware", "Anti-VM: VMware string detected"),
            "VirtualBox_string": (rb"VirtualBox", "Anti-VM: VirtualBox string detected"),
            "VBOX_string": (rb"VBOX", "Anti-VM: VBox string detected"),
            "vmware_services": (rb"vmtoolsd", "Anti-VM: VMware tools service"),
            "qemu_string": (rb"QEMU", "Anti-VM: QEMU string detected"),
            "sleep_instruction": (rb"\x6A\x00\xFF\x15", "Anti-sandbox: Sleep call (evasion)"),
            "wine_check": (rb"wine_get_version", "Anti-sandbox: Wine detection"),
        }
        
        anti_detections = []
        
        try:
            for section in pe.sections:
                section_data = section.get_data()
                
                for technique, (pattern, description) in anti_patterns.items():
                    if pattern in section_data:
                        anti_detections.append(technique)
                        self.add_ioc(
                            "anti_technique",
                            technique,
                            "critical",
                            description
                        )
            
            self.results["anti_detection"]["techniques"] = anti_detections
            
        except Exception as e:
            logger.error(f"Anti-technique detection error: {e}")
    
    def disassemble_entry_point(self):
        """Disassemble entry point"""
        if not str(self.file_path).endswith('.exe'):
            return
        
        try:
            self.update_redis_status("disassembly", 30)
            
            pe = pefile.PE(str(self.file_path))
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            ep_rva = entry_point
            ep_offset = pe.get_offset_from_rva(ep_rva)
            
            with open(self.file_path, 'rb') as f:
                f.seek(ep_offset)
                code = f.read(200)
            
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            
            suspicious_instructions = []
            jmp_count = 0
            call_count = 0
            
            for insn in md.disasm(code, ep_rva):
                if insn.mnemonic == 'jmp':
                    jmp_count += 1
                elif insn.mnemonic == 'call':
                    call_count += 1
                    
                if 'GetProcAddress' in insn.op_str or 'LoadLibrary' in insn.op_str:
                    suspicious_instructions.append(f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
                    self.add_ioc(
                        "dynamic_api_resolution",
                        f"{insn.mnemonic} {insn.op_str}",
                        "high",
                        "Dynamic API resolution at entry point"
                    )
            
            if jmp_count > 10:
                self.add_ioc(
                    "obfuscated_entrypoint",
                    f"{jmp_count} jump instructions in first 200 bytes",
                    "high",
                    "Heavily obfuscated entry point"
                )
            
            if suspicious_instructions:
                self.results["static_analysis"]["entry_point_suspicious"] = suspicious_instructions
            
            pe.close()
            logger.info("Disassembly complete")
            
        except Exception as e:
            logger.error(f"Disassembly error: {e}")
    
    def analyze_strings(self):
        """Extract strings and detect suspicious patterns"""
        try:
            self.update_redis_status("string_analysis", 40)
            
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # ASCII strings (min 4 chars)
            ascii_strings = [s.decode('ascii', errors='ignore') 
                           for s in re.findall(rb'[\x20-\x7E]{4,}', data)]
            
            # Unicode strings
            unicode_strings = [s.decode('utf-16le', errors='ignore') 
                             for s in re.findall(rb'(?:[\x20-\x7E]\x00){4,}', data)]
            
            suspicious_patterns = {
                "ip_address": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                "url": r'https?://[^\s]+',
                "email": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
                "registry_key": r'HKEY_[A-Z_]+\\[^\x00]+',
                "file_path": r'[A-Z]:\\[^\x00]+',
                "crypto_constant": r'(?:AES|RSA|MD5|SHA|DES|HMAC)',
                "c2_indicators": r'(?:cmd\.exe|powershell\.exe|/c\s+|sh\s+-c)',
                "bitcoin_wallet": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                "base64_blob": r'[A-Za-z0-9+/]{40,}={0,2}',
            }
            
            string_analysis = {
                "ascii_count": len(ascii_strings),
                "unicode_count": len(unicode_strings),
                "suspicious_patterns": {}
            }
            
            all_strings = ascii_strings + unicode_strings
            
            for pattern_name, pattern in suspicious_patterns.items():
                matches = []
                for string in all_strings:
                    match = re.search(pattern, string, re.IGNORECASE)
                    if match:
                        matches.append(match.group())
                
                if matches:
                    unique_matches = list(set(matches))[:10]
                    string_analysis["suspicious_patterns"][pattern_name] = unique_matches
                    
                    severity = "critical" if pattern_name in ["c2_indicators", "url", "bitcoin_wallet"] else "medium"
                    self.add_ioc(
                        f"string_{pattern_name}",
                        f"Found {len(unique_matches)} {pattern_name}",
                        severity,
                        f"Suspicious strings: {pattern_name}"
                    )
            
            self.results["static_analysis"]["strings"] = string_analysis
            logger.info("String analysis complete")
            
        except Exception as e:
            logger.error(f"String analysis error: {e}")
    
    def run_yara_scan(self):
        """Run YARA rules against file"""
        try:
            self.update_redis_status("yara_scan", 50)
            
            if not self.yara_rules_path.exists():
                logger.warning(f"YARA rules not found at {self.yara_rules_path}")
                return
            
            yara_files = list(self.yara_rules_path.glob("*.yar"))
            
            if not yara_files:
                logger.warning("No .yar files found")
                return
            
            for yara_file in yara_files:
                try:
                    rules = yara.compile(filepath=str(yara_file))
                    matches = rules.match(str(self.file_path))
                    
                    for match in matches:
                        self.results["yara_matches"].append({
                            "rule": match.rule,
                            "tags": match.tags,
                            "meta": match.meta,
                            "strings": [(s[2].decode() if isinstance(s[2], bytes) else s[2]) for s in match.strings][:5]
                        })
                        
                        severity = "critical" if "malware" in match.tags or "trojan" in match.tags else "high"
                        self.add_ioc(
                            "yara_match",
                            match.rule,
                            severity,
                            f"YARA rule matched: {match.rule}"
                        )
                        
                except Exception as e:
                    logger.warning(f"YARA scan error for {yara_file}: {e}")
            
            logger.info(f"YARA scan complete - {len(self.results['yara_matches'])} matches")
            
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
    
    def run_isolated_execution(self):
        """Run file in isolated environment with strace"""
        if not os.path.exists('/usr/bin/firejail'):
            logger.warning("Firejail not installed, skipping behavioral analysis")
            return
        
        try:
            self.update_redis_status("behavioral_analysis", 60)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                strace_log = os.path.join(tmpdir, 'strace.log')
                
                cmd = [
                    'timeout', str(self.timeout),
                    'firejail',
                    '--noprofile',
                    '--net=none',
                    '--private',
                    '--private-dev',
                    '--private-tmp',
                    '--caps.drop=all',
                    '--seccomp',
                    '--',
                    'strace',
                    '-f',
                    '-e', 'trace=open,openat,creat,unlink,connect,socket,execve,fork,clone,mmap,mprotect,write',
                    '-o', strace_log,
                    str(self.file_path)
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout + 10
                )
                
                if os.path.exists(strace_log):
                    self.parse_strace_log(strace_log)
                
        except subprocess.TimeoutExpired:
            self.add_ioc(
                "execution_timeout",
                f"Execution exceeded {self.timeout}s",
                "medium",
                "Possible sleep/delay evasion technique"
            )
        except Exception as e:
            logger.warning(f"Isolated execution error: {e}")
    
    def parse_strace_log(self, log_path):
        """Parse strace log for behavioral indicators"""
        try:
            with open(log_path, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            behavior = {
                "syscalls": defaultdict(int),
                "file_operations": [],
                "network_operations": [],
                "process_operations": [],
                "memory_operations": []
            }
            
            for line in lines:
                syscall_match = re.match(r'^\d+\s+(\w+)\(', line)
                if syscall_match:
                    syscall = syscall_match.group(1)
                    behavior["syscalls"][syscall] += 1
                
                if any(op in line for op in ['open', 'creat', 'unlink', 'write']):
                    behavior["file_operations"].append(line.strip()[:200])
                    
                    suspicious_paths = [
                        '/etc/passwd', '/etc/shadow', '.ssh', 
                        '/root/', 'autorun.inf', '.lnk'
                    ]
                    
                    if any(path in line.lower() for path in suspicious_paths):
                        self.add_ioc(
                            "suspicious_file_access",
                            line.strip()[:100],
                            "critical",
                            "Access to sensitive system file"
                        )
                
                if any(op in line for op in ['socket', 'connect', 'send']):
                    behavior["network_operations"].append(line.strip()[:200])
                    self.add_ioc(
                        "network_activity",
                        "Network syscalls detected",
                        "high",
                        "Malware attempting network communication"
                    )
                
                if any(op in line for op in ['execve', 'fork', 'clone']):
                    behavior["process_operations"].append(line.strip()[:200])
                    
                    if any(shell in line.lower() for shell in ['cmd.exe', 'powershell', '/bin/sh', '/bin/bash']):
                        self.add_ioc(
                            "suspicious_process",
                            line.strip()[:100],
                            "critical",
                            "Execution of shell/command interpreter"
                        )
                
                if 'mprotect' in line and 'PROT_EXEC' in line:
                    behavior["memory_operations"].append(line.strip()[:200])
                    self.add_ioc(
                        "code_injection",
                        "Memory marked as executable",
                        "critical",
                        "Code injection or shellcode execution"
                    )
            
            self.results["behavioral_analysis"] = behavior
            logger.info("Strace log parsing complete")
            
        except Exception as e:
            logger.error(f"Strace log parsing error: {e}")
    
    def calculate_final_risk(self):
        """Calculate final risk score and severity"""
        total_score = self.results["risk_scoring"]["total_score"]
        
        ioc_count = len(self.results["iocs"])
        confidence = min(100, (ioc_count / 15) * 100)
        
        if self.results["yara_matches"]:
            confidence = min(100, confidence + 20)
        
        if total_score >= 80:
            severity = "CRITICAL"
        elif total_score >= 60:
            severity = "HIGH"
        elif total_score >= 30:
            severity = "MEDIUM"
        elif total_score > 0:
            severity = "LOW"
        else:
            severity = "CLEAN"
        
        self.results["risk_scoring"]["total_score"] = min(100, total_score)
        self.results["risk_scoring"]["severity"] = severity
        self.results["risk_scoring"]["confidence"] = round(confidence, 2)
    
    def run_full_analysis(self):
        """Complete analysis pipeline"""
        logger.info(f"Starting analysis: {self.file_path}")
        
        start_time = time.time()
        
        try:
            logger.info("[1/7] Analyzing metadata...")
            self.analyze_metadata()
            
            logger.info("[2/7] Performing advanced PE analysis...")
            self.analyze_pe_advanced()
            
            logger.info("[3/7] Disassembling entry point...")
            self.disassemble_entry_point()
            
            logger.info("[4/7] Extracting strings...")
            self.analyze_strings()
            
            logger.info("[5/7] Running YARA scan...")
            self.run_yara_scan()
            
            logger.info("[6/7] Running behavioral analysis...")
            self.run_isolated_execution()
            
            logger.info("[7/7] Calculating risk...")
            self.calculate_final_risk()
            
            elapsed_time = time.time() - start_time
            self.results["analysis_time"] = elapsed_time
            
            logger.info(f"Analysis complete - Score: {self.results['risk_scoring']['total_score']}/100 - Severity: {self.results['risk_scoring']['severity']}")
            
            self.update_redis_status("completed", 100)
            
            return self.results
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self.update_redis_status("failed", 0)
            return self.results


# ============================================================================
# FLASK API SERVER
# ============================================================================

def create_api_app():
    """Create Flask API application"""
    app = Flask(__name__)
    CORS(app)
    
    # Redis connection
    try:
        redis_client = redis.Redis(host='redis', port=6379, db=3, decode_responses=True)
        redis_client.ping()
    except:
        redis_client = None
        logger.warning("Redis not available - using in-memory storage")
    
    # In-memory task storage (if Redis unavailable)
    task_storage = {}
    
    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint"""
        return jsonify({
            'status': 'OK',
            'service': 'native-engine',
            'version': '2.1'
        })
    
    @app.route('/api/analyze', methods=['POST'])
    def analyze_file():
        """Analyze file endpoint"""
        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'Empty filename'}), 400
            
            # Save file temporarily
            temp_path = os.path.join('/app/temp', file.filename)
            file.save(temp_path)
            
            # Generate task ID
            task_id = hashlib.sha256(f"{file.filename}{time.time()}".encode()).hexdigest()[:16]
            
            # Run analysis in background thread
            def run_analysis():
                engine = AdvancedNativeEngine(temp_path, task_id=task_id, redis_client=redis_client)
                result = engine.run_full_analysis()
                
                # Store result
                if redis_client:
                    redis_client.hset(f"task:{task_id}", mapping={
                        "result": json.dumps(result),
                        "status": "completed"
                    })
                else:
                    task_storage[task_id] = result
                
                # Cleanup
                try:
                    os.remove(temp_path)
                except:
                    pass
            
            thread = threading.Thread(target=run_analysis, daemon=True)
            thread.start()
            
            return jsonify({
                'task_id': task_id,
                'status': 'submitted',
                'message': 'Analysis queued'
            }), 202
            
        except Exception as e:
            logger.error(f"Analysis endpoint error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/status/<task_id>', methods=['GET'])
    def get_status(task_id):
        """Get task status"""
        try:
            if redis_client:
                status_data = redis_client.hgetall(f"task:{task_id}")
                if not status_data:
                    return jsonify({'error': 'Task not found'}), 404
                
                return jsonify({
                    'task_id': task_id,
                    'status': status_data.get('status', 'unknown'),
                    'progress': int(status_data.get('progress', 0))
                })
            else:
                if task_id not in task_storage:
                    return jsonify({'error': 'Task not found'}), 404
                
                return jsonify({
                    'task_id': task_id,
                    'status': 'completed'
                })
            
        except Exception as e:
            logger.error(f"Status endpoint error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/result/<task_id>', methods=['GET'])
    def get_result(task_id):
        """Get analysis result"""
        try:
            if redis_client:
                result_data = redis_client.hget(f"task:{task_id}", "result")
                if not result_data:
                    return jsonify({'error': 'Result not found'}), 404
                
                result = json.loads(result_data)
                return jsonify(result)
            else:
                if task_id not in task_storage:
                    return jsonify({'error': 'Result not found'}), 404
                
                return jsonify(task_storage[task_id])
            
        except Exception as e:
            logger.error(f"Result endpoint error: {e}")
            return jsonify({'error': str(e)}), 500
    
    return app


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='ZORBOX Native Engine v2.1')
    parser.add_argument('--mode', choices=['analyze', 'server'], default='server')
    parser.add_argument('--file', type=str, help='File to analyze')
    parser.add_argument('--bind', type=str, default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5001)
    parser.add_argument('--debug', action='store_true')
    
    args = parser.parse_args()
    
    if args.mode == 'analyze':
        if not args.file or not os.path.exists(args.file):
            logger.error(f"File not found: {args.file}")
            sys.exit(1)
        
        engine = AdvancedNativeEngine(args.file)
        result = engine.run_full_analysis()
        print(json.dumps(result, indent=2))
        
        # Save report
        output_file = f"/app/reports/{Path(args.file).stem}_{int(time.time())}.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        logger.info(f"Report saved to: {output_file}")
    
    elif args.mode == 'server':
        logger.info(f"Starting API server on {args.bind}:{args.port}")
        app = create_api_app()
        app.run(host=args.bind, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == '__main__':
    main()
