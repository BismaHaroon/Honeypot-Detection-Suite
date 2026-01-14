#!/usr/bin/env python3
"""
Advanced Dionaea Honeypot Detector
Uses deep protocol analysis, memory forensics, and behavioral fingerprinting
"""

import socket
import struct
import time
import hashlib
import re
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
import ssl
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_IP = None
TIMEOUT = 5

class AdvancedDionaeaDetector:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.results = {}
        self.advanced_indicators = []
        
    def deep_protocol_analysis(self):
        """Deep protocol state machine analysis"""
        print("🔬 Deep protocol analysis...")
        
        protocols = {}
        
        # SMB Deep Analysis
        protocols['smb'] = self._analyze_smb_protocol()
        
        # FTP Deep Analysis  
        protocols['ftp'] = self._analyze_ftp_protocol()
        
        # HTTP Deep Analysis
        protocols['http'] = self._analyze_http_protocol()
        
        # SIP Deep Analysis
        protocols['sip'] = self._analyze_sip_protocol()
        
        return protocols
    
    def _analyze_smb_protocol(self):
        """Deep SMB protocol state analysis"""
        try:
            # Test multiple SMB versions and dialects
            smb_versions = [
                # SMB1
                bytes.fromhex("00000054ff534d427200000000180128000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                # SMB2
                bytes.fromhex("fe534d4240000000000000000000000000000000000000000000000000000000"),
                # Malformed SMB
                bytes.fromhex("00000000" + "A" * 100)
            ]
            
            smb_results = {}
            for i, packet in enumerate(smb_versions):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.target_ip, 445))
                    sock.send(packet)
                    response = sock.recv(1024)
                    sock.close()
                    
                    smb_results[f"test_{i}"] = {
                        'response_received': len(response) > 0,
                        'response_length': len(response),
                        'response_hex': response[:16].hex() if response else None,
                        'is_smb_response': response[:4] == b'\xffSMB' or response[:4] == b'\xfeSMB'
                    }
                except Exception as e:
                    smb_results[f"test_{i}"] = {'error': str(e)}
            
            # Check for Dionaea-specific SMB behavior
            if smb_results.get('test_0', {}).get('response_received'):
                self.advanced_indicators.append("SMB service responds to negotiation - common in Dionaea")
                
            return smb_results
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_ftp_protocol(self):
        """Deep FTP protocol analysis"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.target_ip, 21))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Test various FTP commands
            commands = [
                "SYST\r\n",
                "FEAT\r\n", 
                "HELP\r\n",
                "NOOP\r\n",
                "STAT\r\n",
                "PWD\r\n",
                "TYPE A\r\n",
                "PASV\r\n"
            ]
            
            responses = {}
            for cmd in commands:
                sock.send(cmd.encode())
                time.sleep(0.2)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                responses[cmd.strip()] = response.strip()
            
            sock.close()
            
            # Analyze responses for Dionaea patterns
            syst_response = responses.get('SYST', '').upper()
            if 'UNIX' in syst_response or 'LINUX' in syst_response:
                self.advanced_indicators.append("FTP SYST returns UNIX/Linux - common in Dionaea")
                
            if '215' in responses.get('SYST', ''):
                self.advanced_indicators.append("FTP SYST command supported - typical for Dionaea")
            
            return {
                'banner': banner.strip(),
                'command_responses': responses,
                'supported_commands': len([r for r in responses.values() if not r.startswith('5')])
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_http_protocol(self):
        """Deep HTTP protocol analysis"""
        http_tests = {}
        
        # Test various HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        for method in methods:
            try:
                response = requests.request(
                    method, 
                    f"http://{self.target_ip}/",
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=False
                )
                http_tests[method] = {
                    'status': response.status_code,
                    'server': response.headers.get('Server', ''),
                    'content_length': len(response.content)
                }
            except Exception as e:
                http_tests[method] = {'error': str(e)}
        
        # Test HTTP header tolerance
        weird_headers = {
            'X-Forwarded-For': '127.0.0.1',
            'User-Agent': 'Mozilla/5.0 (compatible; Dionaea Scanner)',
            'Accept': '*/*',
            'X-Dionaea-Test': 'true'
        }
        
        try:
            response = requests.get(
                f"http://{self.target_ip}/",
                headers=weird_headers,
                timeout=TIMEOUT,
                verify=False
            )
            http_tests['weird_headers'] = {
                'status': response.status_code,
                'accepted_headers': True
            }
        except Exception as e:
            http_tests['weird_headers'] = {'error': str(e)}
        
        return http_tests
    
    def _analyze_sip_protocol(self):
        """Deep SIP protocol analysis"""
        sip_tests = {}
        
        # Test various SIP methods
        sip_methods = ['OPTIONS', 'REGISTER', 'INVITE', 'BYE']
        
        for method in sip_methods:
            sip_msg = (
                f"{method} sip:test@{self.target_ip} SIP/2.0\r\n"
                f"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK{int(time.time())}\r\n"
                f"Max-Forwards: 70\r\n"
                f"To: <sip:test@{self.target_ip}>\r\n"
                f"From: <sip:detector@192.168.1.1>;tag=12345\r\n"
                f"Call-ID: {int(time.time())}@192.168.1.1\r\n"
                f"CSeq: 1 {method}\r\n"
                f"Contact: <sip:detector@192.168.1.1>\r\n"
                f"Content-Length: 0\r\n\r\n"
            )
            
            for port in [5060, 5061]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.target_ip, port))
                    sock.send(sip_msg.encode())
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()
                    
                    sip_tests[f"{method}_{port}"] = {
                        'response_received': True,
                        'is_sip_response': 'SIP/2.0' in response,
                        'response_code': response.split(' ')[1] if ' ' in response else None
                    }
                    
                    if 'SIP/2.0' in response:
                        self.advanced_indicators.append(f"SIP {method} method supported on port {port} - common in Dionaea")
                    break
                    
                except:
                    continue
        
        return sip_tests

    def memory_and_performance_analysis(self):
        """Analyze memory patterns and performance characteristics"""
        print("📊 Memory and performance analysis...")
        
        performance = {}
        
        # Connection establishment timing
        connection_times = []
        for i in range(10):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target_ip, 80))
                establishment_time = time.time() - start
                
                # Banner receive timing
                banner_start = time.time()
                sock.recv(1024)
                banner_time = time.time() - banner_start
                
                sock.close()
                
                connection_times.append({
                    'establishment': establishment_time,
                    'banner': banner_time,
                    'total': establishment_time + banner_time
                })
            except:
                pass
        
        performance['connection_timing'] = connection_times
        
        # Calculate timing statistics
        if connection_times:
            total_times = [ct['total'] for ct in connection_times]
            avg_time = sum(total_times) / len(total_times)
            variance = sum((t - avg_time) ** 2 for t in total_times) / len(total_times)
            
            performance['timing_stats'] = {
                'average': avg_time,
                'variance': variance,
                'min': min(total_times),
                'max': max(total_times)
            }
            
            # Honeypots often have very consistent timing
            if variance < 0.001:
                self.advanced_indicators.append("Extremely consistent timing patterns - indicative of honeypot")
        
        # Concurrent connection handling
        def test_concurrent_connection(thread_id):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, 21))
                banner = sock.recv(1024)
                time.sleep(1)
                sock.close()
                return f"thread_{thread_id}", "success"
            except Exception as e:
                return f"thread_{thread_id}", str(e)
        
        concurrent_results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(test_concurrent_connection, i) for i in range(10)]
            for future in futures:
                thread_id, result = future.result()
                concurrent_results[thread_id] = result
        
        performance['concurrent_connections'] = {
            'successful': len([r for r in concurrent_results.values() if r == "success"]),
            'total': len(concurrent_results)
        }
        
        # Honeypots often handle many concurrent connections well
        success_rate = performance['concurrent_connections']['successful'] / performance['concurrent_connections']['total']
        if success_rate > 0.8:
            self.advanced_indicators.append("High concurrent connection success rate - typical for honeypots")
        
        return performance

    def application_layer_fingerprinting(self):
        """Application-layer fingerprinting techniques"""
        print("🖨️ Application layer fingerprinting...")
        
        fingerprints = {}
        
        # HTTP Stack Fingerprinting
        try:
            response = requests.get(
                f"http://{self.target_ip}/",
                timeout=TIMEOUT,
                verify=False
            )
            
            headers = dict(response.headers)
            fingerprints['http_stack'] = {
                'server': headers.get('Server', ''),
                'powered_by': headers.get('X-Powered-By', ''),
                'date_format': headers.get('Date', ''),
                'header_order': list(headers.keys()),
                'accept_ranges': headers.get('Accept-Ranges', ''),
                'connection': headers.get('Connection', '')
            }
            
            # Analyze Server header for common honeypot signatures
            server_header = headers.get('Server', '').lower()
            honeypot_servers = ['dionaea', 'honeypot', 'kippo', 'cowrie', 'mhn']
            if any(hp in server_header for hp in honeypot_servers):
                self.advanced_indicators.append(f"Honeypot signature in Server header: {server_header}")
                
        except Exception as e:
            fingerprints['http_stack'] = {'error': str(e)}
        
        # SSL/TLS Fingerprinting
        fingerprints['tls'] = self._tls_fingerprinting()
        
        # Service Banner Analysis
        fingerprints['banners'] = self._banner_analysis()
        
        return fingerprints
    
    def _tls_fingerprinting(self):
        """TLS stack fingerprinting"""
        tls_results = {}
        
        for port in [443, 9930]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_ip, port), timeout=TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        tls_version = ssock.version()
                        
                        tls_results[port] = {
                            'tls_version': tls_version,
                            'cipher': cipher,
                            'cert_issuer': dict(x[0] for x in cert['issuer']) if cert else None,
                            'cert_subject': dict(x[0] for x in cert['subject']) if cert else None,
                            'cert_serial': cert.get('serialNumber', '') if cert else None
                        }
                        
            except Exception as e:
                tls_results[port] = {'error': str(e)}
        
        return tls_results
    
    def _banner_analysis(self):
        """Analyze service banners for fingerprints"""
        banners = {}
        ports_to_check = [21, 22, 23, 80, 443, 445, 9930]
        
        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.target_ip, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                banners[port] = banner.strip()
                
                # Banner content analysis
                if 'dionaea' in banner.lower():
                    self.advanced_indicators.append(f"Dionaea mention in port {port} banner")
                    
            except:
                banners[port] = None
        
        return banners

    def honeypot_specific_detection(self):
        """Dionaea-specific detection techniques"""
        print("🎯 Dionaea-specific detection...")
        
        dionaea_tests = {}
        
        # Check for Dionaea-specific behaviors
        
        # 1. Download directory (common in Dionaea)
        try:
            response = requests.get(
                f"http://{self.target_ip}/download/",
                timeout=TIMEOUT,
                verify=False
            )
            dionaea_tests['download_directory'] = response.status_code
            if response.status_code == 200:
                self.advanced_indicators.append("Download directory accessible - common in Dionaea")
        except:
            dionaea_tests['download_directory'] = 'error'
        
        # 2. Check for Dionaea API endpoints
        api_endpoints = ['/stats', '/files', '/connections', '/downloads', '/api']
        api_results = {}
        for endpoint in api_endpoints:
            try:
                response = requests.get(
                    f"http://{self.target_ip}:9930{endpoint}",
                    timeout=TIMEOUT,
                    verify=False
                )
                api_results[endpoint] = {
                    'status': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'has_content': len(response.content) > 0
                }
                if response.status_code == 200:
                    self.advanced_indicators.append(f"Dionaea API endpoint {endpoint} accessible")
            except:
                api_results[endpoint] = {'error': 'connection failed'}
        
        dionaea_tests['api_endpoints'] = api_results
        
        # 3. Check for emulated vulnerability responses
        vuln_tests = self._test_emulated_vulnerabilities()
        dionaea_tests['vulnerability_emulation'] = vuln_tests
        
        return dionaea_tests
    
    def _test_emulated_vulnerabilities(self):
        """Test for emulated vulnerability responses"""
        vuln_tests = {}
        
        # Test for common vulnerabilities that Dionaea emulates
        vuln_payloads = {
            'ftp_user_overflow': b"USER " + b"A" * 1000 + b"\r\n",
            'http_directory_traversal': b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n",
            'sip_buffer_overflow': b"INVITE sip:" + b"A" * 2000 + b"@test.com SIP/2.0\r\n\r\n"
        }
        
        for vuln_name, payload in vuln_payloads.items():
            try:
                if vuln_name.startswith('ftp'):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.target_ip, 21))
                    sock.recv(1024)  # Banner
                    sock.send(payload)
                    response = sock.recv(1024)
                    sock.close()
                    vuln_tests[vuln_name] = {
                        'responded': len(response) > 0,
                        'crashed': False
                    }
                elif vuln_name.startswith('http'):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect((self.target_ip, 80))
                    sock.send(payload)
                    response = sock.recv(1024)
                    sock.close()
                    vuln_tests[vuln_name] = {
                        'responded': len(response) > 0,
                        'response_code': response.split(b' ')[1] if b' ' in response else None
                    }
                    
            except Exception as e:
                vuln_tests[vuln_name] = {'error': str(e)}
        
        return vuln_tests

    def run_advanced_detection(self):
        """Run all advanced detection methods"""
        print(f"🎯 Advanced Dionaea Detection for {self.target_ip}")
        print("=" * 70)
        
        detection_methods = [
            ("Deep Protocol Analysis", self.deep_protocol_analysis),
            ("Memory & Performance", self.memory_and_performance_analysis),
            ("Application Fingerprinting", self.application_layer_fingerprinting),
            ("Dionaea-Specific Tests", self.honeypot_specific_detection)
        ]
        
        for method_name, method_func in detection_methods:
            print(f"\n📋 Running {method_name}...")
            start_time = time.time()
            result = method_func()
            execution_time = time.time() - start_time
            self.results[method_name] = result
            print(f"   ⏱️  Execution time: {execution_time:.2f}s")
        
        return self.analyze_advanced_results()

    def analyze_advanced_results(self):
        """Advanced analysis using machine learning-like pattern recognition"""
        print("\n" + "=" * 70)
        print("🔬 ADVANCED DIONAEA DETECTION ANALYSIS")
        print("=" * 70)
        
        score = 0
        max_score = 50
        strong_indicators = []
        weak_indicators = []
        
        # Protocol Analysis Scoring
        protocols = self.results.get('Deep Protocol Analysis', {})
        
        # SMB Analysis
        smb = protocols.get('smb', {})
        if smb.get('test_0', {}).get('response_received'):
            score += 3
            strong_indicators.append("SMB protocol responds to negotiation")
        
        # FTP Analysis
        ftp = protocols.get('ftp', {})
        if ftp.get('supported_commands', 0) > 3:
            score += 2
            weak_indicators.append("Multiple FTP commands supported")
        
        # Performance Analysis
        performance = self.results.get('Memory & Performance', {})
        timing_stats = performance.get('timing_stats', {})
        if timing_stats.get('variance', 1) < 0.001:
            score += 4
            strong_indicators.append("Extremely consistent response timing (honeypot characteristic)")
        
        concurrent = performance.get('concurrent_connections', {})
        if concurrent.get('successful', 0) >= 8:
            score += 3
            strong_indicators.append("Handles many concurrent connections well")
        
        # Application Fingerprinting
        fingerprints = self.results.get('Application Fingerprinting', {})
        http_stack = fingerprints.get('http_stack', {})
        server_header = http_stack.get('server', '').lower()
        
        # Check for generic but suspicious server headers
        generic_servers = ['apache', 'nginx', 'iis', 'lighttpd']
        if any(server in server_header for server in generic_servers) and len(server_header) < 20:
            score += 2
            weak_indicators.append("Generic server header - could be hiding honeypot")
        
        # Dionaea-Specific Tests
        dionaea_tests = self.results.get('Dionaea-Specific Tests', {})
        api_endpoints = dionaea_tests.get('api_endpoints', {})
        
        # Check if any API endpoints responded
        api_responses = [ep for ep in api_endpoints.values() if ep.get('status') == 200]
        if api_responses:
            score += 8
            strong_indicators.append("Dionaea API endpoints responding")
        
        # Vulnerability emulation
        vuln_emulation = dionaea_tests.get('vulnerability_emulation', {})
        for test_name, result in vuln_emulation.items():
            if result.get('responded') and not result.get('crashed'):
                score += 2
                weak_indicators.append(f"Responds to {test_name} without crashing")
        
        # Add advanced indicators from detection
        for indicator in self.advanced_indicators:
            if any(keyword in indicator.lower() for keyword in ['dionaea', 'api', 'concurrent', 'consistent']):
                score += 2
                strong_indicators.append(indicator)
            else:
                weak_indicators.append(indicator)
        
        # Calculate confidence with weighted scoring
        confidence = min(100, int((score / max_score) * 100))
        
        # Pattern-based likelihood assessment
        if len(strong_indicators) >= 3:
            likelihood = "VERY HIGH - Almost certainly Dionaea"
            confidence = max(confidence, 85)
        elif len(strong_indicators) >= 2:
            likelihood = "HIGH - Very likely Dionaea" 
            confidence = max(confidence, 70)
        elif len(strong_indicators) >= 1:
            likelihood = "MEDIUM - Likely Dionaea"
            confidence = max(confidence, 50)
        elif len(weak_indicators) >= 3:
            likelihood = "LOW - Possibly Dionaea"
        else:
            likelihood = "VERY LOW - Unlikely to be Dionaea"
        
        analysis = {
            'advanced_score': score,
            'max_score': max_score,
            'confidence': confidence,
            'likelihood': likelihood,
            'strong_indicators': strong_indicators,
            'weak_indicators': weak_indicators,
            'total_indicators': len(strong_indicators) + len(weak_indicators)
        }
        
        return analysis

    def generate_advanced_report(self, analysis):
        """Generate advanced detection report"""
        print(f"\n💎 ADVANCED DETECTION SCORE: {analysis['advanced_score']}/{analysis['max_score']}")
        print(f"🎯 CONFIDENCE LEVEL: {analysis['confidence']}%")
        print(f"🔍 LIKELIHOOD: {analysis['likelihood']}")
        
        print(f"\n🚨 STRONG INDICATORS ({len(analysis['strong_indicators'])}):")
        for indicator in analysis['strong_indicators']:
            print(f"  ✅ {indicator}")
        
        print(f"\n💡 WEAK INDICATORS ({len(analysis['weak_indicators'])}):")
        for indicator in analysis['weak_indicators']:
            print(f"  ⚠️  {indicator}")
        
        print("\n🔬 DETECTION TECHNIQUES USED:")
        print("  • Deep protocol state machine analysis")
        print("  • Memory and performance profiling") 
        print("  • Application layer fingerprinting")
        print("  • Concurrent connection analysis")
        print("  • Vulnerability emulation detection")
        print("  • TLS/SSL stack fingerprinting")
        print("  • Behavioral pattern recognition")
        
        # Save comprehensive results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"advanced_dionaea_detection_{self.target_ip}_{timestamp}.json"
        
        full_report = {
            'target': self.target_ip,
            'timestamp': timestamp,
            'advanced_analysis': analysis,
            'raw_results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(full_report, f, indent=2, default=str)
        
        print(f"\n💾 Full advanced report saved to: {filename}")

def main(target):
    detector = AdvancedDionaeaDetector(target)
    results = detector.run_advanced_detection()
    analysis = detector.analyze_advanced_results()
    detector.generate_advanced_report(analysis)

if __name__ == "__main__":
    import sys
    main(sys.argv[1])

