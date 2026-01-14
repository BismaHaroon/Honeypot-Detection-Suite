#!/usr/bin/env python3
"""
SNARE Honeypot Detection & Fingerprinting Script
Advanced multi-method detection for SNARE (Super Next-gen Advanced Reactive honEypot)
"""

import requests
import socket
import time
import re
import json
import hashlib
import urllib.parse
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import ssl
import http.client

class SnareDetector:
    def __init__(self, target_ip, port=80, timeout=10):
        self.target_ip = target_ip
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{target_ip}:{port}"
        self.results = {
            'target': f"{target_ip}:{port}",
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'score': 0,
            'confidence': 'LOW'
        }
        
        # Configure session with retries
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        
        # SNARE-specific fingerprints
        self.snare_fingerprints = {
            'headers': {
                'server': r'Python/.*aiohttp/',
                'set-cookie': r'sess_uuid=[a-f0-9\-]{36}'
            },
            'content': {
                'redmine': [
                    r'Powered by.*Bitnami Redmine Stack',
                    r'<title>Redmine</title>',
                    r'href="/login".*Sign in'
                ],
                'default_pages': [
                    r'/account/register',
                    r'/projects',
                    r'action-index'
                ]
            },
            'behavior': {
                'fast_response': 50,  # ms threshold
                'consistent_errors': True,
                'no_robots': True
            }
        }
    
    def log_test(self, test_name, result, details=None, weight=1):
        """Log test results with scoring"""
        self.results['tests'][test_name] = {
            'result': result,
            'details': details,
            'weight': weight,
            'timestamp': datetime.now().isoformat()
        }
        if result:
            self.results['score'] += weight
    
    def test_connectivity(self):
        """Test basic connectivity and port response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, self.port))
            sock.close()
            
            if result == 0:
                self.log_test('connectivity', True, "Port is open and responsive", 1)
                return True
            else:
                self.log_test('connectivity', False, f"Port connection failed with code: {result}", 0)
                return False
        except Exception as e:
            self.log_test('connectivity', False, f"Connection error: {str(e)}", 0)
            return False
    
    def fingerprint_http_headers(self):
        """Analyze HTTP headers for SNARE fingerprints"""
        try:
            response = self.session.head(self.base_url, timeout=self.timeout, allow_redirects=True)
            
            headers_analysis = {}
            
            # Server header analysis
            server_header = response.headers.get('Server', '')
            headers_analysis['server'] = server_header
            
            # Check for Python/aiohttp (strong SNARE indicator)
            if re.search(self.snare_fingerprints['headers']['server'], server_header, re.IGNORECASE):
                self.log_test('header_server', True, 
                             f"SNARE-like Server header: {server_header}", 3)
            else:
                self.log_test('header_server', False, 
                             f"Server header: {server_header}", 0)
            
            # Cookie analysis
            cookies = response.headers.get('Set-Cookie', '')
            if 'sess_uuid' in cookies:
                uuid_match = re.search(r'sess_uuid=([a-f0-9\-]{36})', cookies)
                if uuid_match:
                    self.log_test('header_cookie', True,
                                 f"SNARE session UUID: {uuid_match.group(1)}", 2)
            
            # Additional header checks
            unusual_headers = []
            for header in response.headers:
                if header.lower() not in ['server', 'date', 'content-type', 'content-length', 'set-cookie']:
                    unusual_headers.append(f"{header}: {response.headers[header]}")
            
            if unusual_headers:
                self.log_test('unusual_headers', True,
                             f"Unusual headers: {unusual_headers}", 1)
            
            # Check for missing common headers
            common_headers = ['X-Powered-By', 'X-Content-Type-Options', 'X-Frame-Options']
            missing = [h for h in common_headers if h not in response.headers]
            if missing:
                self.log_test('missing_headers', True,
                             f"Missing common security headers: {missing}", 1)
            
            return headers_analysis
            
        except Exception as e:
            self.log_test('header_fingerprint', False, f"Header analysis failed: {str(e)}", 0)
            return {}
    
    def analyze_content_fingerprint(self):
        """Deep content analysis for SNARE signatures"""
        try:
            start_time = time.time()
            response = self.session.get(self.base_url, timeout=self.timeout)
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            
            content_analysis = {
                'length': len(content),
                'response_time': response_time,
                'title': soup.title.string if soup.title else None,
                'forms': len(soup.find_all('form')),
                'links': len(soup.find_all('a')),
                'scripts': len(soup.find_all('script'))
            }
            
            # Check for Redmine fingerprints
            redmine_indicators = 0
            for pattern in self.snare_fingerprints['content']['redmine']:
                if re.search(pattern, content, re.IGNORECASE):
                    redmine_indicators += 1
            
            if redmine_indicators >= 2:
                self.log_test('content_redmine', True,
                             f"Redmine content detected ({redmine_indicators}/3 indicators)", 2)
            
            # Check for default pages/links
            default_page_matches = 0
            for pattern in self.snare_fingerprints['content']['default_pages']:
                if re.search(pattern, content, re.IGNORECASE):
                    default_page_matches += 1
            
            if default_page_matches >= 2:
                self.log_test('content_default_pages', True,
                             f"Default page structures detected", 1)
            
            # Analyze response timing (honeypots often respond too fast)
            if response_time < self.snare_fingerprints['behavior']['fast_response']:
                self.log_test('timing_fast', True,
                             f"Very fast response: {response_time:.2f}ms", 1)
            
            # Calculate content hash for comparison
            content_hash = hashlib.md5(content.encode()).hexdigest()
            self.log_test('content_hash', True, f"Content MD5: {content_hash}", 0)
            
            # Extract and analyze all forms
            forms_data = []
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': [(inp.get('name', ''), inp.get('type', '')) 
                              for inp in form.find_all('input')]
                }
                forms_data.append(form_info)
            
            if forms_data:
                self.log_test('forms_analysis', True,
                             f"Found {len(forms_data)} forms", 1)
            
            return content_analysis
            
        except Exception as e:
            self.log_test('content_analysis', False, f"Content analysis failed: {str(e)}", 0)
            return {}
    
    def test_vulnerability_responses(self):
        """Test how SNARE responds to various attack patterns"""
        tests = [
            ("SQL Injection", "/?id=1'OR'1'='1"),
            ("XSS Basic", "/?q=<script>alert(1)</script>"),
            ("Path Traversal", "/../../../../etc/passwd"),
            ("Command Injection", "/?cmd=whoami"),
            ("LFI", "/?page=../../../etc/passwd"),
            ("XXE", "/?xml=<!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>"),
            ("SSTI", "/?name={{7*7}}"),
            ("NoSQL Injection", "/?user[$ne]=admin")
        ]
        
        suspicious_responses = 0
        test_details = []
        
        for test_name, test_path in tests:
            try:
                test_url = self.base_url + test_path
                start_time = time.time()
                response = self.session.get(test_url, timeout=5)
                response_time = (time.time() - start_time) * 1000
                
                # Check for error messages or suspicious content
                error_keywords = ['sql', 'error', 'syntax', 'mysql', 'script', 
                                 'alert', 'root:', 'daemon:', 'exception', 
                                 'warning', 'undefined', 'invalid']
                
                content_lower = response.text.lower()
                errors_found = [kw for kw in error_keywords if kw in content_lower]
                
                test_result = {
                    'test': test_name,
                    'status': response.status_code,
                    'time': f"{response_time:.2f}ms",
                    'errors': errors_found,
                    'length': len(response.text)
                }
                
                if errors_found:
                    suspicious_responses += 1
                    test_result['suspicious'] = True
                else:
                    test_result['suspicious'] = False
                
                test_details.append(test_result)
                
            except Exception as e:
                test_details.append({
                    'test': test_name,
                    'error': str(e),
                    'suspicious': False
                })
        
        # Analyze results
        if suspicious_responses >= 3:
            self.log_test('vuln_responses', True,
                         f"Multiple vulnerability responses ({suspicious_responses}/{len(tests)})", 3)
        elif suspicious_responses >= 1:
            self.log_test('vuln_responses', True,
                         f"Some vulnerability responses ({suspicious_responses})", 1)
        else:
            self.log_test('vuln_responses', False,
                         "No obvious vulnerability responses", 0)
        
        return test_details
    
    def test_error_consistency(self):
        """Check if error pages are consistent (honeypot characteristic)"""
        error_paths = [
            '/nonexistent-page-12345',
            '/another-fake-page-67890',
            '/test-page-abcdef'
        ]
        
        responses = []
        
        for path in error_paths:
            try:
                response = self.session.get(self.base_url + path, timeout=5)
                responses.append({
                    'path': path,
                    'status': response.status_code,
                    'length': len(response.text),
                    'hash': hashlib.md5(response.text.encode()).hexdigest()
                })
            except:
                continue
        
        if len(responses) >= 2:
            # Check if all error pages are identical
            first_hash = responses[0]['hash']
            identical = all(r['hash'] == first_hash for r in responses[1:])
            
            if identical:
                self.log_test('error_consistency', True,
                             "Identical error pages (honeypot template reuse)", 2)
                return True
            else:
                self.log_test('error_consistency', False,
                             "Varying error pages", 0)
                return False
        
        return False
    
    def check_robots_txt(self):
        """Analyze robots.txt for honeypot indicators"""
        try:
            response = self.session.get(self.base_url + "/robots.txt", timeout=5)
            
            if response.status_code == 200:
                content = response.text
                
                # Check for unusual robots.txt content
                suspicious_patterns = [
                    r'Disallow:\s*/\s*$',  # Disallowing everything
                    r'Allow:\s*/admin',     # Specifically allowing admin
                    r'# Honeypot',          # Comments mentioning honeypot
                    r'Crawl-delay:\s*0'     # No crawl delay
                ]
                
                matches = []
                for pattern in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        matches.append(pattern)
                
                if matches:
                    self.log_test('robots_analysis', True,
                                 f"Suspicious robots.txt patterns: {matches}", 1)
                else:
                    self.log_test('robots_analysis', False,
                                 "Normal robots.txt", 0)
                
                return content
            else:
                self.log_test('robots_missing', True,
                             f"robots.txt not found (404)", 1)
                return None
                
        except Exception as e:
            self.log_test('robots_check', False, f"robots.txt check failed: {str(e)}", 0)
            return None
    
    def test_http_methods(self):
        """Test various HTTP methods for unusual responses"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE']
        
        method_results = []
        
        for method in methods:
            try:
                if method == 'GET':
                    continue  # Already tested
                
                response = self.session.request(method, self.base_url, timeout=5)
                method_results.append({
                    'method': method,
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'allowed': response.status_code != 405
                })
                
            except Exception as e:
                method_results.append({
                    'method': method,
                    'error': str(e),
                    'allowed': False
                })
        
        # Check for unusually permissive methods
        allowed_methods = [r['method'] for r in method_results if r.get('allowed', False)]
        if len(allowed_methods) > 3:  # More than GET, POST, HEAD
            self.log_test('permissive_methods', True,
                         f"Unusually permissive HTTP methods: {allowed_methods}", 1)
        
        return method_results
    
    def perform_deep_content_analysis(self):
        """Perform advanced content analysis"""
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            analysis = {
                'meta_tags': [],
                'javascript_files': [],
                'css_files': [],
                'comments': [],
                'hidden_fields': []
            }
            
            # Extract meta tags
            for meta in soup.find_all('meta'):
                analysis['meta_tags'].append(dict(meta.attrs))
            
            # Extract script sources
            for script in soup.find_all('script', src=True):
                analysis['javascript_files'].append(script['src'])
            
            # Extract CSS links
            for link in soup.find_all('link', rel='stylesheet'):
                if 'href' in link.attrs:
                    analysis['css_files'].append(link['href'])
            
            # Extract HTML comments
            for comment in soup.find_all(text=lambda text: isinstance(text, str) and '<!--' in text):
                analysis['comments'].append(comment.strip())
            
            # Find hidden fields
            for inp in soup.find_all('input', type='hidden'):
                analysis['hidden_fields'].append(dict(inp.attrs))
            
            # Check for honeypot-specific patterns
            honeypot_indicators = 0
            
            # Check for fake version numbers in comments
            version_patterns = [
                r'v?\d+\.\d+(\.\d+)?',  # Version numbers
                r'20\d{2}-\d{2}-\d{2}',  # Dates
                r'build\s*\d+',          # Build numbers
            ]
            
            for comment in analysis['comments']:
                for pattern in version_patterns:
                    if re.search(pattern, comment):
                        honeypot_indicators += 1
                        break
            
            if honeypot_indicators > 0:
                self.log_test('content_metadata', True,
                             f"Found {honeypot_indicators} honeypot indicators in metadata", 1)
            
            return analysis
            
        except Exception as e:
            self.log_test('deep_content', False, f"Deep content analysis failed: {str(e)}", 0)
            return {}
    
    def calculate_confidence(self):
        """Calculate final confidence score"""
        max_score = sum(test['weight'] for test in self.results['tests'].values() 
                       if test['result'])
        
        if self.results['score'] >= 8:
            self.results['confidence'] = 'VERY HIGH'
        elif self.results['score'] >= 6:
            self.results['confidence'] = 'HIGH'
        elif self.results['score'] >= 4:
            self.results['confidence'] = 'MEDIUM'
        elif self.results['score'] >= 2:
            self.results['confidence'] = 'LOW'
        else:
            self.results['confidence'] = 'VERY LOW'
    
    def run_detection(self):
        """Execute all detection tests"""
        print(f"\n{'='*60}")
        print(f"SNARE HONEYPOT DETECTION SUITE")
        print(f"{'='*60}")
        print(f"Target: {self.target_ip}:{self.port}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Run all tests
        print("[1/8] Testing connectivity...")
        self.test_connectivity()
        
        print("[2/8] Fingerprinting HTTP headers...")
        self.fingerprint_http_headers()
        
        print("[3/8] Analyzing content fingerprints...")
        self.analyze_content_fingerprint()
        
        print("[4/8] Testing vulnerability responses...")
        vuln_tests = self.test_vulnerability_responses()
        
        print("[5/8] Checking error consistency...")
        self.test_error_consistency()
        
        print("[6/8] Analyzing robots.txt...")
        self.check_robots_txt()
        
        print("[7/8] Testing HTTP methods...")
        self.test_http_methods()
        
        print("[8/8] Performing deep content analysis...")
        self.perform_deep_content_analysis()
        
        # Calculate final confidence
        self.calculate_confidence()
        
        return self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive detection report"""
        report = {
            'summary': {
                'target': self.results['target'],
                'timestamp': self.results['timestamp'],
                'score': self.results['score'],
                'confidence': self.results['confidence'],
                'tests_performed': len(self.results['tests'])
            },
            'detailed_results': self.results['tests'],
            'recommendations': self.get_recommendations()
        }
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"DETECTION REPORT")
        print(f"{'='*60}")
        
        print(f"\n📊 SUMMARY:")
        print(f"  Target:          {report['summary']['target']}")
        print(f"  Detection Score: {report['summary']['score']}/15")
        print(f"  Confidence:      {report['summary']['confidence']}")
        print(f"  Tests Run:       {report['summary']['tests_performed']}")
        
        print(f"\n🔍 KEY FINDINGS:")
        
        # List positive detections
        positive_tests = [name for name, test in self.results['tests'].items() 
                         if test['result']]
        
        for test_name in positive_tests:
            test_info = self.results['tests'][test_name]
            print(f"  ✓ {test_name}: {test_info.get('details', 'Detected')}")
        
        print(f"\n🎯 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"  • {rec}")
        
        print(f"\n{'='*60}")
        
        # Save report to file
        filename = f"snare_detection_{self.target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📁 Full report saved to: {filename}")
        print(f"{'='*60}")
        
        return report
    
    def get_recommendations(self):
        """Generate recommendations based on findings"""
        recommendations = []
        
        if self.results['confidence'] in ['HIGH', 'VERY HIGH']:
            recommendations.append("This appears to be a SNARE honeypot. Exercise caution.")
            recommendations.append("Any credentials submitted will be logged by the honeypot.")
            recommendations.append("Consider this system as a potential threat intelligence source.")
        
        if any('vuln' in test.lower() for test in self.results['tests']):
            recommendations.append("The system responds to vulnerability probes - characteristic of honeypots.")
        
        if self.results['tests'].get('error_consistency', {}).get('result', False):
            recommendations.append("Identical error pages suggest template-based responses.")
        
        return recommendations

def main(target, port=80):
    detector = SnareDetector(target, port)
    detector.run_detection()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 snare_detector.py <target_ip> [port]")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    main(target, port)

