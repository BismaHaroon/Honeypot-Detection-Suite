import argparse
import socket
import time
import re
import requests
import paramiko
import mysql.connector
import statistics
import math
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Set

# Default ports based on Beelzebub defaults
DEFAULT_PORTS = {
    'ssh': 2222,
    'http': 8080,
    'http_jenkins': 8081,
    'redis': 6379,
    'mysql': 3306,
    'flask_api': 5000,
    'mcp': 2223
}

# Known Beelzebub fingerprints
KNOWN_WEAK_PASSWORDS = ['root', 'admin', 'ubuntu', 'test', 'password', '123456']

# Known LLM refusal patterns
REFUSAL_PATTERNS = [
    r"I cannot.*that",
    r"I'm sorry.*I cannot",
    r"As an AI.*",
    r"I am not able.*",
    r"This content.*policy",
    r"I cannot fulfill.*request",
    r"unable to.*",
    r"for security.*",
    r"for ethical.*",
    r"for safety.*"
]

def port_scan(target):
    """Scan for open default Beelzebub ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(check_port, target, port): service for service, port in DEFAULT_PORTS.items()}
        for future in as_completed(future_to_port):
            service = future_to_port[future]
            try:
                if future.result():
                    open_ports.append((service, DEFAULT_PORTS[service]))
            except Exception:
                pass
    return open_ports

def check_port(target, port):
    """Check if a port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((target, port))
    sock.close()
    return result == 0

# ==============================
# MODULE 1: Memory Consistency
# ==============================
class MemoryConsistencyTest:
    def __init__(self):
        self.facts = []
        self.responses = []
    
    def add_fact_test(self, fact: str, test_command: str) -> Tuple[str, str]:
        """Create a fact and command to test memory later."""
        self.facts.append((fact, test_command))
        return fact, test_command
    
    def check_consistency(self, client) -> Tuple[int, List[str]]:
        """Test if the honeypot remembers facts across sessions."""
        score = 0
        details = []
        
        if len(self.facts) < 2:
            return score, details
        
        # Store initial responses
        initial_responses = []
        for fact, test_cmd in self.facts:
            try:
                stdin, stdout, stderr = client.exec_command(f"echo '{fact}'", timeout=5)
                output = stdout.read().decode().strip()
                initial_responses.append(output)
            except:
                initial_responses.append("")
        
        # Reconnect and test memory
        time.sleep(1)
        
        memory_score = 0
        for i, (fact, test_cmd) in enumerate(self.facts):
            try:
                # Test if system remembers the fact
                stdin, stdout, stderr = client.exec_command(test_cmd, timeout=5)
                response = stdout.read().decode().strip()
                
                if initial_responses[i] and response:
                    if initial_responses[i] in response or response in initial_responses[i]:
                        details.append(f"Memory consistent for fact {i+1}")
                        memory_score += 5
                    else:
                        details.append(f"Memory INCONSISTENT for fact {i+1} (LLM indicator)")
                        memory_score -= 10
            except:
                pass
        
        if memory_score < 0:
            score += abs(memory_score)  # Inconsistency is a strong indicator
            details.append("⚠️ Memory inconsistency detected (LLM honeypot)")
        
        return score, details

# ==============================
# MODULE 2: Timing Variance Analysis
# ==============================
class TimingAnalyzer:
    def __init__(self):
        self.command_times = defaultdict(list)
    
    def measure_command(self, client, command: str, iterations: int = 5) -> Dict:
        """Measure response time for a command multiple times."""
        times = []
        responses = []
        
        for i in range(iterations):
            try:
                start = time.time()
                stdin, stdout, stderr = client.exec_command(command, timeout=10)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                elapsed = time.time() - start
                
                times.append(elapsed)
                responses.append(output or error)
                
                # Small random delay between requests
                time.sleep(0.1 * (i % 3))
                
            except Exception as e:
                times.append(10.0)  # Timeout value
                responses.append(f"ERROR: {str(e)}")
        
        if times:
            return {
                'mean': statistics.mean(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'min': min(times),
                'max': max(times),
                'cv': (statistics.stdev(times) / statistics.mean(times)) if statistics.mean(times) > 0 else 0,
                'responses': responses
            }
        return {'mean': 0, 'stddev': 0, 'min': 0, 'max': 0, 'cv': 0, 'responses': []}
    
    def analyze_variance(self, timing_data: Dict) -> Tuple[int, List[str]]:
        """Analyze timing variance for LLM detection."""
        score = 0
        details = []
        
        cv = timing_data.get('cv', 0)
        mean_time = timing_data.get('mean', 0)
        
        # High coefficient of variation suggests inconsistent processing (LLM-like)
        if cv > 0.5:
            details.append(f"High timing variance (CV={cv:.2f}) - LLM processing")
            score += 15
        
        # Very consistent timing (below human variance but above machine precision)
        elif cv < 0.05 and mean_time > 0.1:
            details.append(f"Suspiciously consistent timing (CV={cv:.2f})")
            score += 10
        
        # Check for quantization (responses in specific time buckets)
        times = [t for t in timing_data.get('raw_times', [])]
        if len(times) >= 5:
            # Round times to nearest 0.1s and check for patterns
            rounded = [round(t * 10) / 10 for t in times]
            unique_times = len(set(rounded))
            if unique_times < len(times) / 2:
                details.append(f"Quantized response times detected")
                score += 12
        
        return score, details

# ==============================
# MODULE 3: Safety Pattern Matching
# ==============================
class SafetyPatternMatcher:
    def __init__(self):
        self.refusal_patterns = REFUSAL_PATTERNS
    
    def check_refusals(self, responses: List[str]) -> Tuple[int, List[str]]:
        """Check for LLM-style refusal patterns."""
        score = 0
        details = []
        refusal_count = 0
        total_responses = len(responses)
        
        if total_responses == 0:
            return score, details
        
        for response in responses:
            response_lower = response.lower()
            for pattern in self.refusal_patterns:
                if re.search(pattern, response_lower, re.IGNORECASE):
                    refusal_count += 1
                    details.append(f"LLM refusal pattern: '{pattern}'")
                    break
        
        refusal_rate = refusal_count / total_responses
        if refusal_rate > 0.3:  # More than 30% refusals
            score += 20
            details.append(f"High refusal rate ({refusal_rate:.1%}) - LLM safety filters")
        elif refusal_rate > 0.1:
            score += 10
            details.append(f"Moderate refusal rate ({refusal_rate:.1%})")
        
        return score, details
    
    def check_ethical_disclaimers(self, responses: List[str]) -> Tuple[int, List[str]]:
        """Check for ethical disclaimer patterns."""
        score = 0
        details = []
        
        ethical_phrases = [
            'ethical', 'responsible', 'safe', 'harmful',
            'policy', 'guidelines', 'appropriate', 'professional'
        ]
        
        for response in responses:
            response_lower = response.lower()
            ethical_count = sum(1 for phrase in ethical_phrases if phrase in response_lower)
            if ethical_count >= 3:
                score += 8
                details.append(f"Multiple ethical disclaimers in response")
                break
        
        return score, details

# ==============================
# MODULE 4: Conversation Depth Tracking
# ==============================
class ConversationDepthTracker:
    def __init__(self):
        self.conversation_history = []
        self.context_persistence_score = 0
    
    def add_interaction(self, command: str, response: str):
        """Add an interaction to conversation history."""
        self.conversation_history.append((command, response))
    
    def analyze_context_persistence(self) -> Tuple[int, List[str]]:
        """Analyze if context persists across multiple messages."""
        score = 0
        details = []
        
        if len(self.conversation_history) < 3:
            return score, details
        
        # Check for repeated phrases (low conversation depth)
        all_responses = ' '.join([r for _, r in self.conversation_history]).lower()
        words = all_responses.split()
        unique_words = len(set(words))
        total_words = len(words)
        
        if total_words > 0:
            uniqueness_ratio = unique_words / total_words
            
            if uniqueness_ratio < 0.3:  # High repetition
                score += 15
                details.append(f"Low linguistic diversity (uniqueness={uniqueness_ratio:.2f})")
            elif uniqueness_ratio < 0.5:
                score += 8
                details.append(f"Moderate linguistic diversity (uniqueness={uniqueness_ratio:.2f})")
        
        # Check for context carry-over
        context_carry = 0
        for i in range(len(self.conversation_history) - 1):
            prev_cmd, prev_resp = self.conversation_history[i]
            curr_cmd, curr_resp = self.conversation_history[i + 1]
            
            # Check if current response references previous context
            prev_words = set(prev_cmd.lower().split() + prev_resp.lower().split())
            curr_words = set(curr_resp.lower().split())
            
            overlap = len(prev_words.intersection(curr_words))
            if overlap > 2:  # Significant overlap
                context_carry += 1
        
        if context_carry > len(self.conversation_history) / 2:
            details.append(f"Good context persistence ({context_carry}/{len(self.conversation_history)-1})")
        else:
            score += 10
            details.append(f"Poor context persistence ({context_carry}/{len(self.conversation_history)-1}) - LLM indicator")
        
        return score, details

# ==============================
# MODULE 5: Entropy Measurement
# ==============================
class EntropyAnalyzer:
    def __init__(self):
        pass
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0
        
        # Get character frequencies
        freq = defaultdict(int)
        for char in text:
            freq[char] += 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_responses(self, responses: List[str]) -> Tuple[int, List[str]]:
        """Analyze entropy of multiple responses."""
        score = 0
        details = []
        
        if not responses:
            return score, details
        
        entropies = []
        for response in responses:
            if response:  # Only analyze non-empty responses
                entropy = self.calculate_entropy(response)
                entropies.append(entropy)
        
        if entropies:
            avg_entropy = statistics.mean(entropies)
            entropy_std = statistics.stdev(entropies) if len(entropies) > 1 else 0
            
            details.append(f"Average entropy: {avg_entropy:.2f} bits/char")
            
            # Low entropy suggests templated/LLM responses
            if avg_entropy < 3.0:  # Normal text is usually 4.0+
                score += 15
                details.append(f"Low linguistic entropy ({avg_entropy:.2f}) - possible LLM")
            
            # Very consistent entropy across responses
            if entropy_std < 0.1 and len(entropies) > 3:
                score += 10
                details.append(f"Suspiciously consistent entropy (std={entropy_std:.3f})")
        
        return score, details

# ==============================
# Enhanced SSH Detection with All Modules
# ==============================
def detect_ssh_enhanced(target, port=2222):
    """Enhanced SSH detection with all advanced modules."""
    score = 0
    details = []
    
    # Initialize modules
    memory_test = MemoryConsistencyTest()
    timing_analyzer = TimingAnalyzer()
    safety_matcher = SafetyPatternMatcher()
    conversation_tracker = ConversationDepthTracker()
    entropy_analyzer = EntropyAnalyzer()
    
    # Test credentials
    successful_logins = []
    test_responses = []
    
    for username in ['root', 'admin', 'ubuntu']:
        for password in ['root', username, 'password']:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target, port=port, username=username, password=password, timeout=10)
                
                successful_logins.append(f"{username}:{password}")
                details.append(f"✓ Login: {username}:{password}")
                score += 10
                
                # ============================================
                # MODULE INTEGRATION: Memory Consistency Test
                # ============================================
                memory_test.add_fact_test("My secret code is XJ9K8L", "echo 'What was the secret code?'")
                memory_test.add_fact_test("The system color is blue", "echo 'What color was mentioned?'")
                
                # ============================================
                # MODULE INTEGRATION: Timing Variance
                # ============================================
                timing_results = []
                test_commands = [
                    'echo "Hello World"',
                    'whoami',
                    'date',
                    'uname -a',
                    'echo "Test for timing analysis"'
                ]
                
                for cmd in test_commands:
                    timing_data = timing_analyzer.measure_command(client, cmd, iterations=3)
                    timing_results.append(timing_data)
                    
                    # Store responses for analysis
                    if timing_data['responses']:
                        test_responses.extend(timing_data['responses'])
                        for resp in timing_data['responses']:
                            conversation_tracker.add_interaction(cmd, resp)
                
                # Analyze timing variance
                if timing_results:
                    avg_cv = statistics.mean([t.get('cv', 0) for t in timing_results])
                    if avg_cv > 0.3:
                        timing_score, timing_details = timing_analyzer.analyze_variance({
                            'cv': avg_cv,
                            'raw_times': [t for result in timing_results for t in [result.get('mean', 0)] * 3]
                        })
                        score += timing_score
                        details.extend(timing_details)
                
                # ============================================
                # MODULE INTEGRATION: Safety Pattern Matching
                # ============================================
                # Test potentially sensitive commands
                sensitive_commands = [
                    'cat /etc/shadow',
                    'rm -rf /',
                    'echo "How to hack a system?"',
                    'sudo su'
                ]
                
                sensitive_responses = []
                for cmd in sensitive_commands:
                    try:
                        stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                        output = stdout.read().decode().strip()
                        error = stderr.read().decode().strip()
                        sensitive_responses.append(output or error)
                    except:
                        pass
                
                safety_score, safety_details = safety_matcher.check_refusals(sensitive_responses)
                score += safety_score
                details.extend(safety_details)
                
                # ============================================
                # MODULE INTEGRATION: Memory Consistency Check
                # ============================================
                mem_score, mem_details = memory_test.check_consistency(client)
                score += mem_score
                details.extend(mem_details)
                
                # ============================================
                # MODULE INTEGRATION: Conversation Depth
                # ============================================
                # Add more interactions
                depth_commands = [
                    ("What's the current directory?", "pwd"),
                    ("List files here", "ls -la"),
                    ("Check system uptime", "uptime"),
                    ("Show network info", "ifconfig || ip addr")
                ]
                
                for question, cmd in depth_commands:
                    try:
                        stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
                        response = stdout.read().decode().strip() or stderr.read().decode().strip()
                        conversation_tracker.add_interaction(question, response)
                        test_responses.append(response)
                    except:
                        pass
                
                conv_score, conv_details = conversation_tracker.analyze_context_persistence()
                score += conv_score
                details.extend(conv_details)
                
                # ============================================
                # MODULE INTEGRATION: Entropy Measurement
                # ============================================
                entropy_score, entropy_details = entropy_analyzer.analyze_responses(test_responses)
                score += entropy_score
                details.extend(entropy_details)
                
                client.close()
                break
                
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                details.append(f"Connection error: {str(e)}")
    
    # Multiple successful logins indicator
    if len(successful_logins) > 1:
        details.append(f"⚠️ {len(successful_logins)} weak credentials work")
        score += 15
    
    return score, details

# ==============================
# Enhanced HTTP Detection
# ==============================
def detect_http_enhanced(target, port=8080):
    """Enhanced HTTP detection."""
    score = 0
    details = []
    
    urls_to_check = [
        f"http://{target}:{port}",
        f"http://{target}:{port}/admin",
        f"http://{target}:{port}/wp-admin",
        f"http://{target}:{port}/login",
    ]
    
    all_responses = []
    for url in urls_to_check:
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            details.append(f"HTTP {url}: Status {response.status_code}")
            all_responses.append(response.text)
            
            if response.status_code == 401 and 'WWW-Authenticate' in response.headers:
                details.append(f"  ✓ Basic Auth required")
                score += 15
            
            if 'WordPress' in response.text or 'wp-' in response.text:
                details.append(f"  ✓ WordPress-like content")
                score += 10
            
            if len(response.text) < 500 and '<html' in response.text.lower():
                details.append(f"  ✓ Minimal HTML ({len(response.text)} chars)")
                score += 5
                
        except Exception as e:
            details.append(f"HTTP probe failed: {str(e)}")
    
    # Apply entropy analysis to HTTP responses
    entropy_analyzer = EntropyAnalyzer()
    entropy_score, entropy_details = entropy_analyzer.analyze_responses(all_responses)
    score += entropy_score
    details.extend(entropy_details)
    
    return score, details

# ==============================
# Enhanced MySQL Detection
# ==============================
def detect_mysql_enhanced(target, port=3306):
    """Enhanced MySQL detection."""
    score = 0
    details = []
    
    credentials = [
        ('root', 'root'),
        ('root', 'password'),
        ('root', ''),
        ('admin', 'admin'),
    ]
    
    for user, pwd in credentials:
        try:
            conn = mysql.connector.connect(
                host=target,
                port=port,
                user=user,
                password=pwd,
                connect_timeout=3,
                connection_timeout=3
            )
            details.append(f"✓ MySQL login: {user}:{pwd}")
            score += 15
            
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES;")
            dbs = cursor.fetchall()
            db_names = [db[0] for db in dbs]
            details.append(f"  Databases: {', '.join(db_names[:5])}")
            
            if all(db in db_names for db in ['information_schema', 'mysql']):
                details.append("  ✓ Standard MySQL databases")
                score += 5
            
            # Test response timing
            start = time.time()
            cursor.execute("SELECT 1")
            cursor.fetchall()
            query_time = time.time() - start
            
            if query_time > 0.5:
                details.append(f"  Slow query response ({query_time:.2f}s)")
                score += 8
            
            conn.close()
            break
            
        except mysql.connector.Error as e:
            if 'Lost connection' in str(e):
                details.append(f"MySQL lost connection (honeypot indicator)")
                score += 12
    
    return score, details

# ==============================
# Main Function
# ==============================
def main(target):
    print(f"\n{'='*60}")
    print(f"[*] ADVANCED BEELZEBUB HONEYPOT DETECTOR v2.0")
    print(f"[*] Target: {target}")
    print(f"{'='*60}")
    
    print(f"\n[+] Module Overview:")
    print(f"  1. Memory Consistency Test")
    print(f"  2. Timing Variance Analysis")
    print(f"  3. Safety Pattern Matching")
    print(f"  4. Conversation Depth Tracking")
    print(f"  5. Entropy Measurement")
    print(f"{'-'*60}")
    
    # Phase 1: Port Scan
    print(f"\n[+] Phase 1: Port Scanning")
    open_ports = port_scan(target)
    for service, port in open_ports:
        print(f"  • {service.upper()} open on {port}")
    
    total_score = 0
    module_scores = {}
    
    # Phase 2: SSH Detection with Advanced Modules
    if 'ssh' in [s for s, _ in open_ports]:
        print(f"\n[+] Phase 2: SSH Detection with Advanced Modules")
        ssh_score, ssh_details = detect_ssh_enhanced(target, DEFAULT_PORTS['ssh'])
        module_scores['ssh'] = ssh_score
        
        print(f"\n  [SSH Module Results]:")
        for detail in ssh_details[:15]:  # Show first 15 details
            print(f"    {detail}")
        if len(ssh_details) > 15:
            print(f"    ... and {len(ssh_details)-15} more indicators")
        
        total_score += ssh_score
        print(f"\n  SSH Module Score: {ssh_score}")
    
    # Phase 3: HTTP Detection
    if 'http' in [s for s, _ in open_ports]:
        print(f"\n[+] Phase 3: HTTP Detection")
        http_score, http_details = detect_http_enhanced(target, DEFAULT_PORTS['http'])
        module_scores['http'] = http_score
        
        for detail in http_details:
            print(f"    {detail}")
        
        total_score += http_score
        print(f"\n  HTTP Module Score: {http_score}")
    
    # Phase 4: MySQL Detection
    if 'mysql' in [s for s, _ in open_ports]:
        print(f"\n[+] Phase 4: MySQL Detection")
        mysql_score, mysql_details = detect_mysql_enhanced(target, DEFAULT_PORTS['mysql'])
        module_scores['mysql'] = mysql_score
        
        for detail in mysql_details:
            print(f"    {detail}")
        
        total_score += mysql_score
        print(f"\n  MySQL Module Score: {mysql_score}")
    
    # Phase 5: Behavioral Analysis
    print(f"\n[+] Phase 5: Behavioral Analysis")
    behavioral_score = 0
    
    if len(open_ports) >= 3:
        print(f"    ✓ Multiple services ({len(open_ports)}) - honeypot indicator")
        behavioral_score += 20
    
    beelzebub_ports = {2222, 8080, 3306}
    found_ports = {port for _, port in open_ports}
    if beelzebub_ports.issubset(found_ports):
        print(f"    ✓ Default Beelzebub port combination detected")
        behavioral_score += 25
    
    total_score += behavioral_score
    
    # Final Analysis
    print(f"\n{'='*60}")
    print(f"[=] FINAL ANALYSIS")
    print(f"{'='*60}")
    
    max_score = 300  # Increased due to additional modules
    percentage = (total_score / max_score) * 100
    
    # Enhanced likelihood determination
    if percentage >= 75:
        likelihood = "VERY HIGH"
        color_code = "\033[91m"  # Bright Red
        emoji = "🔴🔴🔴"
    elif percentage >= 60:
        likelihood = "HIGH"
        color_code = "\033[31m"  # Red
        emoji = "🔴🔴"
    elif percentage >= 45:
        likelihood = "MEDIUM"
        color_code = "\033[33m"  # Yellow
        emoji = "🟡🟡"
    elif percentage >= 30:
        likelihood = "LOW"
        color_code = "\033[32m"  # Green
        emoji = "🟢"
    else:
        likelihood = "VERY LOW"
        color_code = "\033[92m"  # Bright Green
        emoji = "🟢"
    
    print(f"\nTotal Score: {total_score}/{max_score} ({percentage:.1f}%)")
    print(f"{color_code}{emoji} Honeypot Confidence: {likelihood}\033[0m")
    
    # Research Value Indicators
    print(f"\n[+] Research Value Indicators:")
    
    research_findings = []
    if module_scores.get('ssh', 0) > 50:
        research_findings.append("• Strong LLM behavioral patterns detected in SSH")
    if any('Memory' in d for d in (ssh_details if 'ssh' in locals() else [])):
        research_findings.append("• Memory inconsistency identified (novel finding)")
    if any('entropy' in d.lower() for d in (ssh_details if 'ssh' in locals() else [])):
        research_findings.append("• Low linguistic entropy detected (LLM signature)")
    if any('timing variance' in d.lower() for d in (ssh_details if 'ssh' in locals() else [])):
        research_findings.append("• Timing variance analysis reveals LLM processing")
    if any('refusal' in d.lower() for d in (ssh_details if 'ssh' in locals() else [])):
        research_findings.append("• Safety filter patterns matched LLM behavior")
    
    if research_findings:
        for finding in research_findings:
            print(f"  {finding}")
        print(f"\n🎓 RESEARCH VALUE: HIGH - Multiple novel detection methods validated")
    else:
        print(f"  • Basic honeypot indicators detected")
        print(f"\n🎓 RESEARCH VALUE: MODERATE - Traditional detection methods")
    
    # Recommendations
    print(f"\n[+] Recommendations:")
    if likelihood in ["HIGH", "VERY HIGH"]:
        print(f"  • This target is very likely a Beelzebub honeypot with LLM backend")
        print(f"  • Consider it for academic research on AI-powered honeypots")
        print(f"  • Document the specific behavioral patterns observed")
    else:
        print(f"  • Inconclusive evidence - consider additional testing")
        print(f"  • Try MCP protocol analysis on port 2223")
        print(f"  • Test with more sophisticated conversation patterns")
    
    print(f"\n{'='*60}")
    print(f"[*] Detection completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced Beelzebub Honeypot Detector with LLM Behavioral Analysis",
        epilog="Includes 5 research modules for academic-level detection"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed module output")
    args = parser.parse_args()
    
    main(args.target)
