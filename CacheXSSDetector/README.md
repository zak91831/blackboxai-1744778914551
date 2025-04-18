# CacheXSSDetector

A sophisticated security tool for detecting and analyzing cache-based Cross-Site Scripting (XSS) vulnerabilities in web applications.

## Overview

CacheXSSDetector is a specialized security testing tool designed to identify, verify, and assess cache-based XSS vulnerabilities. It focuses on detecting vulnerabilities that arise from the interaction between web caching systems and XSS payloads, including cache poisoning, cache deception, and persistent XSS through cache mechanisms.

## Features

### Core Scanning Capabilities
- **URL Path Manipulation**: Advanced path traversal and parameter manipulation for cache testing
- **Cache Behavior Analysis**: In-depth analysis of caching patterns and behaviors
- **XSS Payload Generation**: Sophisticated payload generation with cache-aware capabilities
- **Response Analysis**: Comprehensive analysis of cached responses and XSS indicators
- **Advanced XSS Detection**: Context-aware XSS vulnerability detection with WAF bypass capabilities
- **XSS0r Integration**: Powerful crawling, form testing, and comprehensive scanning similar to XSS0r
- **Custom Header Injection**: Detection of XSS vulnerabilities via HTTP request headers
- **Adaptive Rate Limiting**: Smart throttling to avoid WAF blocks and blacklisting

### Request Components
- **HTTP Client**: Robust HTTP client with cache-aware request handling
- **Header Manipulation**: Advanced header manipulation for cache testing
- **Proxy Integration**: Seamless integration with HTTP/HTTPS proxies

### Verification System
- **Multi-Client Simulator**: Simulation of multiple clients for cache behavior testing
- **Cache Hit/Miss Detection**: Accurate detection of cache hits and misses
- **False Positive Reduction**: Advanced algorithms to minimize false positives

### Reporting System
- **Vulnerability Classification**: Detailed classification of discovered vulnerabilities
- **Risk Assessment**: Comprehensive risk assessment and scoring
- **Report Generation**: Detailed HTML reports with visualizations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CacheXSSDetector.git
cd CacheXSSDetector
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python cachexssdetector.py scan --url https://example.com
```

### Advanced Options
```bash
python cachexssdetector.py scan \
    --url https://example.com \
    --config custom_config.yaml \
    --output report.html \
    --verbose
```

### XSS0r CLI Tool
The XSS0r integration provides an advanced CLI tool for comprehensive XSS scanning:

```bash
# Basic usage
python xss0r_cli.py http://example.com

# Advanced options
python xss0r_cli.py http://example.com \
    --depth 3 \
    --max-urls 100 \
    --delay 1.5 \
    --output scan_results.json \
    --verbose

# Testing with blind XSS
python xss0r_cli.py http://example.com \
    --blind-xss \
    --callback-url https://your-callback-server.com/callback
    
# Header-based XSS testing
python xss0r_cli.py http://example.com \
    --header-tests 5
```

Options:
- `--depth`: Maximum crawl depth (default: 2)
- `--max-urls`: Maximum URLs to scan per domain (default: 50)
- `--delay`: Delay between requests in seconds (default: 1.0)
- `--output`: Output file for scan results (JSON format)
- `--verbose`: Enable detailed logging
- `--no-forms`: Disable form testing
- `--no-headers`: Disable header testing
- `--header-tests`: Number of header tests per URL (default: 3)
- `--no-cookies`: Disable cookie testing
- `--no-dom`: Disable DOM-based XSS testing
- `--blind-xss`: Enable blind XSS testing
- `--callback-url`: URL for blind XSS callbacks

### Rate-Limited XSS0r CLI Tool
For scanning sensitive targets or avoiding WAF blocks, use the rate-limited version:

```bash
# Basic usage with adaptive rate limiting
python rate_limited_cli.py http://example.com

# Control rate limiting settings
python rate_limited_cli.py http://example.com \
    --rate-limit 30 \
    --delay 2.0 \
    --header-tests 3
```

Additional Rate-Limited Options:
- `--rate-limit`: Maximum requests per minute (default: 60)
- `--disable-adaptive`: Disable adaptive rate limiting (fixed rate)

### Configuration
Create a custom configuration file by copying and modifying the default config:
```bash
cp config.yaml custom_config.yaml
```

## Configuration Options

### Core Scanner Settings
```yaml
core_scanner:
  url_path:
    max_path_depth: 5
    max_params: 10
  cache_behavior:
    min_samples: 5
    time_window: 300
  rate_limiting:
    enabled: true
    requests_per_minute: 60
    adaptive: true
```

### Request Components Settings
```yaml
request_components:
  http_client:
    timeout: 30
    max_retries: 3
  header_manipulation:
    enable_custom_headers: true
    test_headers:
      - User-Agent
      - X-Forwarded-For
      - Referer
```

### Verification System Settings
```yaml
verification_system:
  multi_client:
    num_clients: 5
    request_delay: 1.0
```

## Architecture

### Core Components
1. **Core Scanner**
   - URL Path Manipulation
   - Cache Behavior Analysis
   - XSS Payload Generator
   - Response Analyzer
   - Custom Header Injector
   - Rate-Limited Scanner

2. **Request Components**
   - HTTP Client
   - Header Manipulation
   - Proxy Integration

3. **Verification System**
   - Multi-Client Simulator
   - Cache Hit/Miss Detector
   - False Positive Reducer

4. **Reporting Module**
   - Vulnerability Classification
   - Risk Assessment
   - Report Generator

5. **Utilities**
   - Rate Limiter
   - WAF Detection & Bypass

## Development

### Setting Up Development Environment
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 cachexssdetector/
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Security Considerations

### Responsible Testing
- Always obtain proper authorization before testing
- Follow responsible disclosure practices
- Be aware of potential impact on cache systems
- Use rate limiting to avoid disrupting services

### Limitations
- Tool may impact cache performance
- Some detection methods are timing-dependent
- False positives may occur in complex scenarios
- WAF evasion techniques should only be used legally

## Best Practices

### Cache Testing
1. Start with non-critical systems
2. Monitor cache performance during testing
3. Clear caches after testing
4. Document all findings and impacts

### Mitigation Strategies
1. Implement proper cache controls
2. Use cache segmentation
3. Apply security headers
4. Regular cache validation
5. Filter and sanitize headers

## Troubleshooting

### Common Issues
1. **Connection Errors**
   - Check proxy settings
   - Verify target accessibility
   - Review network configurations

2. **False Positives**
   - Adjust confidence thresholds
   - Increase verification rounds
   - Review cache patterns

3. **Performance Issues**
   - Adjust request delays
   - Reduce parallel requests
   - Monitor system resources

4. **WAF Blocks**
   - Enable adaptive rate limiting
   - Reduce scan intensity
   - Use stealthier scanning techniques

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors
- Special thanks to the security research community
- Inspired by various web security tools and research

## Contact

- Report bugs: [Issue Tracker](https://github.com/yourusername/CacheXSSDetector/issues)
- Follow updates: [Twitter](https://twitter.com/yourusername)
- Questions: [Discussions](https://github.com/yourusername/CacheXSSDetector/discussions)
