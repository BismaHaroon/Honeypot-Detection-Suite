# 🕵️ Honeypot Detection Suite

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Research](https://img.shields.io/badge/security-research-orange)](https://github.com/topics/honeypot)

A comprehensive suite for detecting various types of honeypots, including Cowrie, Snare, Dionaea, and Beelzebub. This tool helps security researchers and penetration testers identify honeypots during reconnaissance.

## ✨ Features

- **Multi-Honeypot Detection**: Identify Cowrie (SSH), Snare (HTTP), Dionaea (multi-protocol), and Beelzebub honeypots
- **Comprehensive Analysis**: Banner analysis, behavioral testing, protocol anomalies, and timing analysis
- **Safe Testing**: Pre-configured safe test datasets for legal testing in Europe
- **Automated Testing Suite**: Batch testing and performance evaluation
- **Detailed Reporting**: JSON, CSV, and HTML reports with performance metrics

## 📋 Supported Honeypots

| Honeypot | Protocol | Detection Methods |
|----------|----------|-------------------|
| **Cowrie** | SSH/Telnet | Banner analysis, authentication patterns, command execution behavior |
| **Snare** | HTTP/HTTPS | Response headers, error patterns, file system emulation |
| **Dionaea** | Multi-protocol | Service fingerprinting, protocol anomalies, malware capture detection |
| **Beelzebub** | Various | Behavioral analysis, response timing, service emulation |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/honeypot-detection-suite.git
cd honeypot-detection-suite

# Set up the environment
chmod +x setup_test_environment.sh
./setup_test_environment.sh

# Install dependencies
pip install -r requirements.txt

### **Usage**
# Test a single target for Cowrie honeypot
python detector.py 192.168.1.100 cowrie

# Test for Snare honeypot (web)
python detector.py example.com snare

# Test for Dionaea honeypot
python detector.py 192.168.1.101 dionaea

# Test for Beelzebub honeypot
python detector.py 192.168.1.102 beelzebub
