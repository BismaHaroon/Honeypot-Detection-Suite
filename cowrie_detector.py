import socket
import time
import paramiko
import subprocess
import platform
import re
import hashlib
import json
import ssl
import http.client
import threading
from datetime import datetime
import struct
import select

TARGET_IP = None
TARGET_PORT = 2222
TIMEOUT = 10

class ComprehensiveSSHHoneypotDetector:
    def __init__(self, target_ip, target_port=2222):
        self.target_ip = target_ip
        self.target_port = target_port
        self.results = {}
        
    def banner_analysis(self):
        """Analyze SSH banner for honeypot indicators."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            start_time = time.time()
            sock.connect((self.target_ip, self.target_port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            response_time = time.time() - start_time
            sock.close()
            
            # More aggressive Cowrie detection patterns
            cowrie_indicators = [
                "OpenSSH_9.",  # Very recent versions are suspicious
                "OpenSSH_8.",  # Also recent
                "OpenSSH_7.",  # Common in Cowrie
                "Debian-",     # Any Debian string
                "Ubuntu-",     # Any Ubuntu string
                "p1",          # Common patch version pattern
                "p2",
            ]
            
            # Check if banner contains suspicious patterns
            is_suspicious = False
            suspicious_count = 0
            
            for pattern in cowrie_indicators:
                if pattern in banner:
                    suspicious_count += 1
            
            # If we found multiple suspicious patterns, flag it
            is_likely_cowrie = suspicious_count >= 2
            
            # Also check for common Cowrie banners
            common_cowrie_banners = [
                "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
                "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "SSH-2.0-OpenSSH_7.4",
                "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
                "SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8"
            ]
            
            is_exact_match = banner in common_cowrie_banners
            
            return {
                'banner': banner,
                'response_time': response_time,
                'is_known_cowrie': is_likely_cowrie or is_exact_match,
                'version_too_new': self._check_version_recency(banner),
                'has_debian_string': 'Debian' in banner,
                'has_ubuntu_string': 'Ubuntu' in banner,
                'banner_length': len(banner),
                'banner_raw': banner,
                'suspicious_patterns': suspicious_count,
                'is_exact_match': is_exact_match
            }
        except Exception as e:
            return {'error': str(e)}
            
    def _check_version_recency(self, banner):
        """Check if banner shows suspiciously recent version."""
        match = re.search(r'OpenSSH_(\d+\.\d+)', banner)
        if match:
            version = float(match.group(1))
            # Cowrie often uses very recent versions
            return version >= 8.0  # Lowered threshold to 8.0
        return False
    
    def key_exchange_analysis(self):
        """Analyze SSH key exchange behavior."""
        try:
            start_time = time.time()
            sock = socket.create_connection((self.target_ip, self.target_port), timeout=TIMEOUT)
            sock.settimeout(5)
            
            # Send SSH identification
            sock.send(b"SSH-2.0-paramiko_3.6.0\r\n")
            
            # Receive server identification
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            banner_time = time.time() - start_time
            
            # Try to get key exchange init with better packet
            # SSH_MSG_KEXINIT packet structure
            kex_packet = bytearray([
                0x00, 0x00, 0x01, 0xf4,  # Length: 500
                0x14,                    # SSH_MSG_KEXINIT
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Cookie
                0x00, 0x00, 0x00, 0x00,  # kex_algorithms_length
                0x00, 0x00, 0x00, 0x00,  # server_host_key_algorithms_length
                0x00, 0x00, 0x00, 0x00,  # encryption_algorithms_client_to_server_length
                0x00, 0x00, 0x00, 0x00,  # encryption_algorithms_server_to_client_length
                0x00, 0x00, 0x00, 0x00,  # mac_algorithms_client_to_server_length
                0x00, 0x00, 0x00, 0x00,  # mac_algorithms_server_to_client_length
                0x00, 0x00, 0x00, 0x00,  # compression_algorithms_client_to_server_length
                0x00, 0x00, 0x00, 0x00,  # compression_algorithms_server_to_client_length
                0x00, 0x00, 0x00, 0x00,  # languages_client_to_server_length
                0x00, 0x00, 0x00, 0x00,  # languages_server_to_client_length
                0x00,                    # first_kex_packet_follows
                0x00, 0x00, 0x00, 0x00   # Reserved
            ])
            
            sock.send(kex_packet)
            try:
                sock.settimeout(3)
                kex_response = sock.recv(4096)
                kex_present = len(kex_response) > 0
                kex_time = time.time() - start_time
            except:
                kex_present = False
                kex_time = banner_time
            
            sock.close()
            
            return {
                'server_banner': response[:100] if response else None,
                'kex_init_received': kex_present,
                'kex_time': kex_time,
                'banner_time': banner_time,
                'response_length': len(response) if response else 0
            }
        except Exception as e:
            return {'error': str(e), 'kex_time': 0}
            
    
    def authentication_behavior(self):
        """Test authentication behavior patterns."""
        results = {
            'max_attempts': 0,
            'auth_exceptions': [],
            'timing_patterns': [],
            'consistent_timing': True,
            'all_failed': True
        }
        
        # Test multiple invalid credentials
        usernames = ['admin', 'root', 'test', 'user', 'guest', 'ubuntu', 'debian', 'pi', 'raspberry']
        timings = []
        
        for i, username in enumerate(usernames[:5]):  # Limit to 5 attempts
            try:
                start_time = time.time()
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Try with wrong password
                client.connect(self.target_ip, self.target_port, 
                             username=username, password='wrong_password_' + str(i),
                             look_for_keys=False, allow_agent=False, timeout=5)
                auth_time = time.time() - start_time
                client.close()
                results['max_attempts'] += 1
                timings.append(auth_time)
                results['all_failed'] = False  # Authentication succeeded!
            except paramiko.AuthenticationException:
                auth_time = time.time() - start_time
                results['max_attempts'] += 1
                timings.append(auth_time)
            except Exception as e:
                results['auth_exceptions'].append(str(e))
                # Don't break, try next username
        
        results['timing_patterns'] = timings
        
        # Check if timing is consistent (honeypots often have artificial delays)
        if len(timings) > 2:
            avg_time = sum(timings) / len(timings)
            variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
            results['consistent_timing'] = variance < 0.05  # Lower threshold for consistency
        
        return results
    
    def command_execution_test(self):
        """Test command execution behavior (if we can authenticate)."""
        # Try common default credentials for Cowrie - ADD MORE
        common_creds = [
            ('root', 'root'),           
            ('admin', 'admin'),         
            ('test', 'test'),           
            ('guest', 'guest'),         
            ('ubuntu', 'ubuntu'),       
            ('root', 'password'),       
            ('root', '123456'),         
            ('pi', 'raspberry'),        
            ('user', 'user'),           
            ('sshuser', 'sshuser'),
            ('root', ''),  # Empty password
            ('root', 'toor'),  # root backwards
            ('admin', 'admin123'),
            ('test', 'test123')
        ]
        
        for username, password in common_creds:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.target_ip, self.target_port,
                             username=username, password=password,
                             look_for_keys=False, allow_agent=False, timeout=5)
                
                # Test command execution with BETTER Cowrie-specific checks
                commands = {
                    'uname': 'uname -a',
                    'id': 'id',
                    'pwd': 'pwd',
                    'ls_root': 'ls -la /',
                    'ls_etc': 'ls -la /etc/passwd 2>/dev/null || echo "no access"',
                    'ps': 'ps aux | head -10',
                    'whoami': 'whoami',
                    'hostname': 'hostname',
                    'df': 'df -h 2>/dev/null || echo "command failed"',
                    'fake_command': 'this_command_should_not_exist_12345',
                    'cowrie_check': 'ls -la /opt/cowrie 2>/dev/null || ls -la /cowrie 2>/dev/null || echo "cowrie not found"',
                    'python_cowrie': 'python3 -c "print(\'Cowrie test\')" 2>/dev/null || echo "no python"',
                    'env_check': 'env | grep -i "COWRIE\|HONEYPOT" 2>/dev/null || echo "no env vars"',
                    'honeydb_check': 'ls -la /var/log/honeydb 2>/dev/null || echo "no honeydb"',
                    # Cowrie-specific file system checks
                    'cowrie_logs': 'ls -la /var/log/cowrie* 2>/dev/null || echo "no cowrie logs"',
                    'cowrie_config': 'find /etc /opt -name "*cowrie*" -type f 2>/dev/null | head -5 || echo "no configs"'
                }
                
                command_results = {}
                cowrie_evidence = []
                suspicious_behaviors = []
                
                for name, cmd in commands.items():
                    try:
                        stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        error = stderr.read().decode('utf-8', errors='ignore')
                        exit_status = stdout.channel.recv_exit_status()
                        
                        # Check for Cowrie indicators
                        output_lower = output.lower()
                        
                        # DIRECT EVIDENCE
                        if 'cowrie' in output_lower:
                            cowrie_evidence.append(f"'cowrie' found in {name}")
                        
                        if 'honeypot' in output_lower:
                            cowrie_evidence.append(f"'honeypot' found in {name}")
                            
                        # INDIRECT EVIDENCE
                        if name == 'ls_root':
                            lines = output.strip().split('\n')
                            if len(lines) < 8:
                                line_count = len(lines)
                                suspicious_behaviors.append(f"Limited root directory ({line_count} items)")
                        
                        if name == 'uname':
                            if 'linux' in output_lower and len(output.strip()) < 40:
                                suspicious_behaviors.append(f"Short uname output")
                        
                        if name == 'fake_command' and exit_status == 0:
                            suspicious_behaviors.append(f"Fake command succeeded (suspicious)")
                        
                        command_results[name] = {
                            'output': output.strip(),
                            'error': error.strip(),
                            'return_code': exit_status,
                            'output_length': len(output.strip()),
                            'has_cowrie': 'cowrie' in output_lower,
                            'line_count': len(output.strip().split('\n'))
                        }
                    except Exception as e:
                        command_results[name] = {'error': str(e)}
                
                client.close()
                
                return {
                    'success': True, 
                    'username': username, 
                    'password': password,
                    'commands': command_results,
                    'cowrie_evidence': cowrie_evidence,
                    'suspicious_behaviors': suspicious_behaviors,
                    'cowrie_detected': len(cowrie_evidence) > 0,
                    'evidence_count': len(cowrie_evidence)
                }
                
            except (paramiko.AuthenticationException, paramiko.SSHException, socket.timeout, Exception) as e:
                continue
        
        return {'success': False}
    
    def service_fingerprinting(self):
        """Check for additional services commonly run with honeypots."""
        common_honeypot_ports = [21, 23, 80, 443, 2222, 8080, 8888, 3306, 5432, 5900, 5901]
        open_ports = {}
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    # Try to get service banner
                    try:
                        sock.settimeout(3)
                        if port in [80, 443, 8080, 8888]:
                            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        open_ports[port] = banner[:100]  # First 100 chars
                    except:
                        open_ports[port] = "No banner"
                sock.close()
            except:
                pass
        
        threads = []
        for port in common_honeypot_ports:
            thread = threading.Thread(target=check_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=5)
        
        return open_ports
    
    def protocol_anomalies(self):
        """Check for protocol implementation anomalies."""
        anomalies = []
        
        # Test with malformed SSH connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, self.target_port))
            
            # Send invalid SSH version
            sock.send(b"SSH-INVALID-1.0\r\n")
            response = sock.recv(1024)
            if response:
                anomalies.append("responded_to_invalid_ssh")
            
            # Send garbage data
            sock.send(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            try:
                response = sock.recv(1024)
                if response:
                    anomalies.append("responded_to_garbage")
            except socket.timeout:
                pass
            
            # Send very long string
            sock.send(b"SSH-2.0-" + b"A" * 1000 + b"\r\n")
            try:
                response = sock.recv(1024)
                if response:
                    anomalies.append("responded_to_oversized_banner")
            except socket.timeout:
                pass
                
            sock.close()
        except Exception as e:
            anomalies.append(f"protocol_test_error: {str(e)}")
        
        return anomalies
    
    def ttl_analysis(self):
        """Analyze TTL for OS fingerprinting."""
        try:
            cmd = ["ping", "-c", "1", self.target_ip] if platform.system() != "Windows" else ["ping", "-n", "1", self.target_ip]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            m = re.search(r"ttl[=|:](\d+)", out.stdout, re.IGNORECASE)
            if m:
                ttl = int(m.group(1))
                # Common initial TTL values
                if ttl <= 64:
                    return {'ttl': ttl, 'likely_os': 'Linux/Unix', 'original_ttl': 64}
                elif ttl <= 128:
                    return {'ttl': ttl, 'likely_os': 'Windows', 'original_ttl': 128}
                else:
                    return {'ttl': ttl, 'likely_os': 'Unknown', 'original_ttl': 255}
        except:
            pass
        return None
    
    def traffic_analysis(self):
        """Analyze network traffic patterns and timing."""
        results = {
            'packet_timing_variance': 0,
            'response_consistency': False,  # Changed default to False
            'latency_patterns': []
        }
        
        # Test multiple connections to analyze timing patterns
        latencies = []
        successful_connections = 0
        
        for i in range(5):
            try:
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)  # Reduced timeout from TIMEOUT (10) to 5 seconds
                sock.connect((self.target_ip, self.target_port))
                connect_time = time.time() - start_time
                
                # Get banner timing
                start_banner = time.time()
                banner = sock.recv(1024)
                banner_time = time.time() - start_banner
                
                sock.close()
                latencies.append({
                    'connect': connect_time,
                    'banner': banner_time,
                    'total': connect_time + banner_time
                })
                successful_connections += 1
            except Exception as e:
                latencies.append({'error': str(e)})
        
        results['latency_patterns'] = latencies
        results['successful_connections'] = successful_connections
        
        # Calculate variance in response times - ONLY if we have enough successful connections
        if successful_connections > 1:
            total_times = [l['total'] for l in latencies if 'total' in l]
            if len(total_times) > 1:  # Check we have at least 2 total times
                avg_time = sum(total_times) / len(total_times)
                variance = sum((t - avg_time) ** 2 for t in total_times) / len(total_times)
                results['packet_timing_variance'] = variance
                results['response_consistency'] = variance < 0.05  # Very consistent timing suggests honeypot
        
        return results
    
    def algorithm_testing(self):
        try:
            # Try connecting with paramiko to detect supported algorithms
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Record which connection attempts succeed
            results = {
                'weak_ssh1_support': False,
                'no_key_exchange': False
            }
            
            # Test SSH-1 protocol (obsolete, rarely supported)
            try:
                # This would typically fail on modern systems
                sock = socket.create_connection((self.target_ip, self.target_port), timeout=5)
                sock.send(b"SSH-1.5-paramiko\r\n")
                response = sock.recv(1024)
                if b"SSH-1" in response:
                    results['weak_ssh1_support'] = True
                sock.close()
            except:
                pass
                
            return results
        except Exception as e:
            return {'error': str(e)}
        
    
    def behavioral_analysis(self):
        """Test interactive shell behavior and filesystem emulation."""
        results = {
            'shell_behavior': {},
            'filesystem_emulation': {},
            'command_responses': {}
        }
        
        # Try to authenticate with common credentials first
        test_creds = [('root', 'root'), ('admin', 'admin')]
        
        for username, password in test_creds:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.target_ip, self.target_port,
                             username=username, password=password,
                             look_for_keys=False, allow_agent=False, timeout=5)
                
                # Test shell behavior
                shell_tests = {
                    'help_command': 'help',
                    'question_mark': '?',
                    'empty_command': '',
                    'cowrie_specific': 'cowrie',
                    'long_output': 'cat /dev/urandom | head -c 1000'
                }
                
                for test_name, command in shell_tests.items():
                    try:
                        stdin, stdout, stderr = client.exec_command(command, timeout=3)
                        output = stdout.read().decode('utf-8', errors='ignore')
                        error = stderr.read().decode('utf-8', errors='ignore')
                        results['shell_behavior'][test_name] = {
                            'output': output[:500],  # Limit output size
                            'error': error,
                            'has_output': len(output.strip()) > 0
                        }
                    except Exception as e:
                        results['shell_behavior'][test_name] = {'error': str(e)}
                
                client.close()
                results['auth_success'] = True
                break
                
            except Exception:
                continue
        
        if not results.get('auth_success'):
            results['auth_success'] = False
        
        return results
    
    def web_interface_check(self):
        """Check for web-based honeypot interfaces."""
        web_paths = [
            "/", "/admin", "/cgi-bin/", "/honeypot", "/cowrie", 
            "/kippo", "/dionaea", "/glastopf", "/admin/login",
            "/webconsole", "/monitoring"
        ]
        
        results = {}
        
        # Check HTTP
        for port in [80, 8080, 8888]:
            try:
                conn = http.client.HTTPConnection(self.target_ip, port, timeout=5)
                for path in web_paths:
                    try:
                        conn.request("HEAD", path)
                        response = conn.getresponse()
                        if response.status in [200, 301, 302]:
                            results[f"http_{port}{path}"] = {
                                'status': response.status,
                                'headers': dict(response.getheaders())
                            }
                    except:
                        pass
                conn.close()
            except:
                pass
        
        # Check HTTPS
        for port in [443, 8443]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                conn = http.client.HTTPSConnection(self.target_ip, port, timeout=5, context=context)
                for path in web_paths:
                    try:
                        conn.request("HEAD", path)
                        response = conn.getresponse()
                        if response.status in [200, 301, 302]:
                            results[f"https_{port}{path}"] = {
                                'status': response.status,
                                'headers': dict(response.getheaders())
                            }
                    except:
                        pass
                conn.close()
            except:
                pass
        
        return results
    
    def ssl_certificate_analysis(self):
        """Analyze SSL certificates for honeypot indicators."""
        results = {}
        
        for port in [443, 8443, 2222]:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_ip, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        results[port] = {
                            'certificate': cert,
                            'cipher': cipher,
                            'has_certificate': cert is not None,
                            'is_self_signed': self._check_self_signed(cert),
                            'subject': cert.get('subject', []) if cert else None
                        }
            except Exception as e:
                results[port] = {'error': str(e)}
        
        return results
    
    def _check_self_signed(self, cert):
        """Check if certificate is self-signed."""
        if not cert:
            return False
        try:
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))
            return subject == issuer
        except:
            return False
    
    def run_comprehensive_detection(self):
        """Run all detection methods."""
        print(f"🔍 Comprehensive SSH Honeypot Detection for {self.target_ip}:{self.target_port}")
        print("=" * 70)
        
        # Run all tests
        tests = [
            ("Banner Analysis", self.banner_analysis),
            ("TTL Analysis", self.ttl_analysis),
            ("Key Exchange", self.key_exchange_analysis),
            ("Authentication Behavior", self.authentication_behavior),
            ("Service Fingerprinting", self.service_fingerprinting),
            ("Protocol Anomalies", self.protocol_anomalies),
            ("Traffic Analysis", self.traffic_analysis),
            ("Algorithm Testing", self.algorithm_testing),
            ("Behavioral Analysis", self.behavioral_analysis),
            ("Web Interface Check", self.web_interface_check),
            ("SSL Certificate Analysis", self.ssl_certificate_analysis),
            ("Command Execution Test", self.command_execution_test)
        ]
        
        for test_name, test_func in tests:
            print(f"\n📋 Running {test_name}...")
            start_time = time.time()
            result = test_func()
            execution_time = time.time() - start_time
            self.results[test_name] = result
            print(f"   ⏱️  Execution time: {execution_time:.2f}s")
            print(f"   📊 Result keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}")
        
        return self.analyze_comprehensive_results()
    
    def analyze_comprehensive_results(self):
        """Analyze all results and provide honeypot likelihood."""
        score = 0
        indicators = []
        details = {}
        
        # Banner analysis (Max: 4 points)
        banner_info = self.results.get('Banner Analysis', {})
        if banner_info.get('is_known_cowrie'):
            score += 3
            indicators.append("Known Cowrie banner pattern")
        if banner_info.get('version_too_new'):
            score += 2  # Increased from 1
            indicators.append("Suspiciously recent SSH version")
        if banner_info.get('has_debian_string') or banner_info.get('has_ubuntu_string'):
            score += 1
            indicators.append("Contains Debian/Ubuntu string in banner")
        details['banner_score'] = 3 if banner_info.get('is_known_cowrie') else 0
        
        # Authentication behavior (Max: 4 points)
        auth_info = self.results.get('Authentication Behavior', {})
        if not auth_info.get('all_failed', True):  # If any authentication succeeded
            score += 3  # Strong indicator
            indicators.append("Accepted invalid credentials (honeypot behavior)")
        if auth_info.get('max_attempts', 0) >= 3:
            score += 1
            indicators.append("Multiple failed login attempts allowed")
        if auth_info.get('consistent_timing', False):
            score += 1
            indicators.append("Artificial timing patterns in authentication")
        details['auth_score'] = 3 if not auth_info.get('all_failed', True) else 0
        
        # Key exchange (Max: 2 points)
        kex_info = self.results.get('Key Exchange', {})
        if kex_info.get('kex_time', 0) > 2.0:
            score += 2
            indicators.append("Slow key exchange (emulation overhead)")
        details['kex_score'] = 2 if kex_info.get('kex_time', 0) > 2.0 else 0
        
        # Service fingerprinting (Max: 2 points)
        services = self.results.get('Service Fingerprinting', {})
        if len(services) > 1:  # More than just SSH
            score += 2
            indicators.append("Multiple services running (common for honeypots)")
        details['service_score'] = 2 if len(services) > 1 else 0
        
        # Protocol anomalies (Max: 3 points)
        anomalies = self.results.get('Protocol Anomalies', [])
        if "responded_to_invalid_ssh" in anomalies:
            score += 2
            indicators.append("Responded to invalid SSH protocol")
        if "responded_to_garbage" in anomalies:
            score += 1
            indicators.append("Responded to garbage data")
        details['protocol_score'] = 2 if "responded_to_invalid_ssh" in anomalies else (1 if "responded_to_garbage" in anomalies else 0)
        
        # Traffic analysis (Max: 2 points)
        traffic_info = self.results.get('Traffic Analysis', {})
        if traffic_info.get('response_consistency', False):
            score += 2
            indicators.append("Artificial traffic patterns detected")
        details['traffic_score'] = 2 if traffic_info.get('response_consistency') else 0
        
        # Algorithm testing (Max: 2 points)
        algo_info = self.results.get('Algorithm Testing', {})
        if algo_info.get('weak_ssh1_support', False):
            score += 2
            indicators.append("Supports weak SSH-1 protocol")
        details['algo_score'] = 2 if algo_info.get('weak_ssh1_support') else 0
        
        # Behavioral analysis (Max: 4 points)
        behavior_info = self.results.get('Behavioral Analysis', {})
        if behavior_info.get('auth_success', False):
            score += 3
            indicators.append("Accepted default credentials in behavioral test")
            # Check for suspicious shell behavior
            shell_behavior = behavior_info.get('shell_behavior', {})
            for test, result in shell_behavior.items():
                if isinstance(result, dict) and result.get('has_output', False):
                    output = result.get('output', '').lower()
                    if 'cowrie' in output or 'honeypot' in output:
                        score += 1
                        indicators.append(f"Cowrie-specific response in {test}")
                        break
        details['behavior_score'] = 3 if behavior_info.get('auth_success') else 0
        
        # Command execution (Max: 8 points) - Improved scoring
        cmd_info = self.results.get('Command Execution Test', {})
        if cmd_info.get('success', False):
            score += 3
            indicators.append(f"Authenticated as {cmd_info.get('username', 'unknown')}")
            
            evidence_count = cmd_info.get('evidence_count', 0)
            if evidence_count > 0:
                score += min(3, evidence_count)  # Up to 3 points for evidence
                indicators.append(f"Found {evidence_count} Cowrie evidence items")
                for evidence in cmd_info.get('cowrie_evidence', [])[:3]:
                    indicators.append(f"  - {evidence}")
            
            # Suspicious behaviors
            suspicious = cmd_info.get('suspicious_behaviors', [])
            if suspicious:
                score += min(2, len(suspicious))
                indicators.append(f"{len(suspicious)} suspicious shell behaviors")
        
        details['cmd_score'] = 3 if cmd_info.get('success') else 0
        
        # Web interface (Max: 1 point)
        web_info = self.results.get('Web Interface Check', {})
        if len(web_info) > 0:
            score += 1
            indicators.append("Web management interface detected")
        details['web_score'] = 1 if len(web_info) > 0 else 0
        
        # SSL certificates (Max: 1 point)
        ssl_info = self.results.get('SSL Certificate Analysis', {})
        for port, info in ssl_info.items():
            if info.get('is_self_signed', False):
                score += 1
                indicators.append("Self-signed SSL certificate detected")
                break
        details['ssl_score'] = 1 if any(info.get('is_self_signed', False) for info in ssl_info.values()) else 0
        
        # TTL analysis (Max: 1 point) - Added
        ttl_info = self.results.get('TTL Analysis', {})
        if ttl_info:
            if ttl_info.get('likely_os') == 'Linux/Unix':
                score += 1
                indicators.append("Linux TTL detected (common for honeypots)")
        details['ttl_score'] = 1 if ttl_info and ttl_info.get('likely_os') == 'Linux/Unix' else 0
        
        max_possible_score = 30  # Increased from 23
        confidence = min(100, int((score / max_possible_score) * 100))
        
        # Adjust thresholds
        likely_threshold = 10 # Lowered from 12
        certain_threshold = 15 # Lowered from 15
        
        return {
            'honeypot_score': score,
            'max_score': max_possible_score,
            'confidence': confidence,
            'indicators': indicators,
            'details': details,
            'likely_honeypot': score >= likely_threshold,
            'certain_honeypot': score >= certain_threshold,
            'is_cowrie': self._check_cowrie_specific_indicators()
        }
        
    def _check_cowrie_specific_indicators(self):
        """Check for specific Cowrie honeypot indicators."""
        cowrie_indicators = []
        
        # Check banner for Cowrie patterns
        banner_info = self.results.get('Banner Analysis', {})
        if banner_info.get('is_known_cowrie'):
            cowrie_indicators.append("Cowrie-like banner")
        
        # Check command outputs for Cowrie references
        cmd_info = self.results.get('Command Execution Test', {})
        if cmd_info.get('cowrie_detected', False):
            cowrie_indicators.append("Cowrie references in command outputs")
        
        # Check behavioral analysis
        behavior_info = self.results.get('Behavioral Analysis', {})
        shell_behavior = behavior_info.get('shell_behavior', {})
        for test, result in shell_behavior.items():
            if isinstance(result, dict):
                output = result.get('output', '').lower()
                if 'cowrie' in output:
                    cowrie_indicators.append(f"Cowrie in {test} test")
        
        return len(cowrie_indicators) > 0
def main(target):
    detector = ComprehensiveSSHHoneypotDetector(target, 2222)
    detector.run_comprehensive_detection()
    print("\n" + "=" * 70)
    print("🎯 COMPREHENSIVE HONEYPOT ANALYSIS RESULTS")
    print("=" * 70)
    
    final_analysis = detector.analyze_comprehensive_results()
    
    print(f"\n📊 Honeypot Detection Score: {final_analysis['honeypot_score']}/{final_analysis['max_score']}")
    print(f"🎯 Confidence Level: {final_analysis['confidence']}%")
    print(f"🔍 Likely Honeypot: {'YES' if final_analysis['likely_honeypot'] else 'NO'}")
    print(f"🚨 Certain Honeypot: {'YES' if final_analysis['certain_honeypot'] else 'NO'}")
    
    print("\n📋 Detected Indicators:")
    for indicator in final_analysis['indicators']:
        print(f"  • {indicator}")
    
    print("\n🔬 Detailed Scoring:")
    for test_name, score in final_analysis['details'].items():
        print(f"  {test_name}: {score} point(s)")
    
    if final_analysis['certain_honeypot']:
        print("\n🚨 HIGH CONFIDENCE: This is DEFINITELY a honeypot!")
        print("   ⚠️  Exercise extreme caution - all interactions are being monitored")
    elif final_analysis['likely_honeypot']:
        print("\n⚠️  MEDIUM CONFIDENCE: This is LIKELY a honeypot")
        print("   🔍 Consider additional verification before any sensitive interactions")
    else:
        print("\n✅ LOW CONFIDENCE: This appears to be a genuine SSH server")
        print("   💡 Normal security precautions still apply")
    
    # Save comprehensive results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"comprehensive_honeypot_scan_{TARGET_IP}_{timestamp}.json"
    
    full_results = {
        'target': f"{TARGET_IP}:{TARGET_PORT}",
        'timestamp': timestamp,
        'scan_results': detector.results,
        'analysis': final_analysis
    }
    
    with open(filename, 'w') as f:
        json.dump(full_results, f, indent=2, default=str)
    
    print(f"\n💾 Full comprehensive results saved to: {filename}")
    print(f"📁 File includes all raw data for further analysis")

if __name__ == "__main__":
    import sys
    main(sys.argv[1])

