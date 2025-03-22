# GHOST SCANNER - Admin Panel Finder

A penetration testing tool for identifying vulnerable admin panels and control interfaces on target systems.

## Features

- Multi-threaded scanning of over 400 known admin endpoints
- Real-time progress monitoring with detailed results
- Five operational modes for different testing requirements
- JSON and TXT export formats for reporting
- Proxy support and SSL verification options

## Installation

```bash
# Clone the repository
git clone https://github.com/cybertituss/GhostScanner.git
cd GhostScanner

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

```bash
python main.py <target_domain>
```

## Command Options

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--threads`, `-t` | Number of parallel threads | `--threads 10` |
| `--output`, `-o` | Save results to file | `--output results.json` |
| `--format` | Output format (json or txt) | `--format txt` |
| `--proxy`, `-p` | Use proxy for requests | `--proxy http://127.0.0.1:8080` |
| `--timeout` | Connection timeout in seconds | `--timeout 10` |
| `--no-verify` | Disable SSL certificate verification | `--no-verify` |
| `--verbose`, `-v` | Enable detailed logs | `--verbose` |
| `--mode`, `-m` | Set operational mode | `--mode aggressive` |
| `--help`, `-h` | Show help information | `--help` |

## Operational Modes

### 1. Stealth (Default)
Balanced approach with moderate thread count and timeouts.
```bash
python main.py target.com
```

### 2. Aggressive
Faster scanning with triple the thread count and shorter timeouts.
```bash
python main.py target.com --mode aggressive
```

### 3. Deep Scan
Additional paths, more threads, and longer timeouts for thorough testing.
```bash
python main.py target.com --mode deep
```

### 4. Passive
Uses HEAD requests to minimize footprint on the target.
```bash
python main.py target.com --mode passive
```

### 5. Evasion
Advanced WAF bypass techniques with realistic browser simulation.
```bash
python main.py target.com --mode evasion
```

## Export Formats

### JSON (Default)
```bash
python main.py target.com --output results.json
```

### Text
```bash
python main.py target.com --output report.txt --format txt
```

## Examples

```bash
# Basic scan
python main.py example.com

# Advanced scan with output
python main.py example.com --threads 20 --output scan.json --mode deep

# Using a proxy with verbose output
python main.py example.com --proxy http://127.0.0.1:8080 --verbose

# Text report output
python main.py example.com --output report.txt --format txt
```

## Response Code Analysis

- **200**: Potential vulnerable entry point
- **301/302**: Redirect (possible honeypot)
- **403**: Access denied by firewall
- **404**: Endpoint not found
- **500**: Server error (potential vulnerability)

## Troubleshooting

- For SSL certificate issues: Use `--no-verify`
- For slow scanning: Increase threads with `--threads 30`
- If you get timeout errors: Increase timeout with `--timeout 10`

## Legal Disclaimer

This tool is developed for **authorized penetration testing only**. Use against systems without proper authorization may violate applicable laws.

## Contact

Operator: [@cybertituss](https://twitter.com/cybertituss)
