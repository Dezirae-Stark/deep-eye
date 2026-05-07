<center>
<img src="./assets/Screenshot 2025-10-20 150312.png" height="400">
</center>

# Deep Eye 🔍

An advanced AI-driven vulnerability scanner and penetration testing tool that integrates multiple AI providers (OpenAI, Grok, OLLAMA, Claude) with comprehensive security testing modules for automated bug hunting, intelligent payload generation, and professional reporting.

> **🔱 Fork notice — `Dezirae-Stark/deep-eye` (v1.4.0)**
>
> This fork carries the **Shadowbroker recon-bridge integration**: pre-scan engagement-scope authorization (mandatory expiry, include/exclude rules) plus OSINT enrichment (Shodan, region dossier, CT logs, geopolitics) consumed via HMAC-signed `/bridge/*`. Hard fail-closed on out-of-scope targets, missing keys, or unreachable bridge. See **[docs/recon-bridge-runbook.md](docs/recon-bridge-runbook.md)** for setup, or PRs [#1](https://github.com/Dezirae-Stark/deep-eye/pull/1) (Plan A, 21 tasks) and [#2](https://github.com/Dezirae-Stark/deep-eye/pull/2) (Codex R3 hardening — advisory-only local scope check so a stale local manifest no longer blocks bridge-allowed scans, dual-stack `getaddrinfo` for lab `region_lock` URL resolution, `BridgeStartError`-wrapped client construction errors) for the diff against upstream. **72/72 tests** pass (incl. 4 real-bin smoke tests); Codex Round 4 cleared PR #2 with no findings. Server-side companion: [`Dezirae-Stark/Shadowbroker`](https://github.com/Dezirae-Stark/Shadowbroker).

![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## 🚀 Features

### Core Capabilities
- **Multi-AI Provider Support**: Dynamic switching between OpenAI, Grok, OLLAMA, and Claude
- **Intelligent Payload Generation**: AI-powered, CVE-aware, context-sensitive payloads
- **Comprehensive Scanning**: 45+ attack methods with framework-specific tests
- **Advanced Reconnaissance**: Passive OSINT, DNS enumeration, subdomain discovery
- **Professional Reporting**: PDF/HTML/JSON reports with OSINT intelligence and executive summaries
- **Collaborative Scanning**: Team-based distributed scanning with session management
- **Custom Plugin System**: Extend Deep Eye with your own vulnerability scanners
- **Multi-Channel Notifications**: Real-time alerts via Email, Slack, and Discord

### Vulnerability Detection

#### Core Vulnerabilities
- SQL Injection (Error-based, Blind, Time-based)
- Cross-Site Scripting (XSS)
- Command Injection
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- Path Traversal
- CSRF (Cross-Site Request Forgery)
- Open Redirect
- CORS Misconfiguration
- Security Headers Analysis

#### v1.3.0 Additional Vulnerabilities
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Server-Side Template Injection (SSTI)
- CRLF Injection
- Host Header Injection
- LDAP Injection
- XML Injection
- Insecure Deserialization
- Authentication Bypass
- Information Disclosure
- Sensitive Data Exposure
- JWT Vulnerabilities
- Broken Authentication

#### v1.1.0 Advanced Modules
- **API Security Testing** (OWASP API Top 10 2023)
- **GraphQL Security** (Introspection, Depth limits, Batch attacks)
- **Business Logic Flaws** (Price manipulation, Workflow bypass, Race conditions)
- **Authentication Testing** (Session management, JWT, OAuth, MFA bypass)
- **File Upload Vulnerabilities** (Unrestricted upload, Path traversal, Type bypass)
- **Collaborative Scanning** (Team-based distributed scanning)

#### v1.2.0 Advanced Modules
- **WebSocket Testing** (Origin validation, Auth, Injection, DoS protection)
- **ML-Based Anomaly Detection** (Behavioral analysis, Pattern recognition)
- **Interactive HTML Reports** (Charts, Filtering, Real-time search)
- **Enhanced OSINT** (Google dorking, Breach databases, CT logs, GitHub/Pastebin)
- **Advanced Payload Obfuscation** (11+ techniques for WAF bypass)

#### v1.3.0 New Features
- **Custom Plugin System** (Extend with your own scanners)
- **Multi-Channel Notifications** (Email, Slack, Discord alerts)
- **Enhanced OSINT Reporting** (Reconnaissance data in all reports)

And 17+ more attack vectors

## 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- API keys for AI providers (at least one):
  - OpenAI API Key
  - Anthropic (Claude) API Key
  - Grok API Key
  - OLLAMA (local installation)

## 🔧 Installation

### Quick Install (Recommended)

**Windows:**
```powershell
.\scripts\install.ps1
```

**Linux/Mac:**
```bash
chmod +x scripts/install.sh
./scripts/install.sh
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/zakirkun/deep-eye.git
cd deep-eye
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure AI providers:
```bash
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your API keys
```

## 🎯 Usage

### Quick Start
```bash
# Scan with target from CLI
python deep_eye.py -u https://example.com

# Scan with configuration file
python deep_eye.py -c myconfig.yaml

# Verbose mode
python deep_eye.py -u https://example.com -v
```

### Configuration-Driven Scanning
All scan options are configured in `config/config.yaml`:

```yaml
scanner:
  target_url: "https://example.com"  # Default target
  ai_provider: "openai"               # AI provider
  default_depth: 2                    # Crawl depth
  default_threads: 5                  # Thread count
  enable_recon: true                  # Enable reconnaissance
  full_scan: false                    # Full/quick scan mode
  proxy: ""                           # Proxy settings
  custom_headers: {}                  # Custom headers

reporting:
  enabled: true                       # Auto-generate reports
  output_directory: "reports"         # Report directory
  default_format: "html"              # Report format
```

Then run:
```bash
python deep_eye.py
```

### Command Line Options (Minimal)
```
-u, --url              Target URL (overrides config)
-c, --config           Configuration file path (default: config/config.yaml)
-v, --verbose          Enable verbose output
--version              Show version and exit
--no-banner            Disable banner display
```

**Note:** All scanning options (depth, threads, AI provider, scan mode, proxy, etc.) are now configured in `config.yaml` for better management and repeatability.

## 📁 Project Structure

```
deep-eye/
├── core/                      # Core scanning engine
├── ai_providers/              # AI provider integrations
├── modules/                   # Security testing modules
├── utils/                     # Utility functions
├── config/                    # Configuration files
├── templates/                 # Report templates
├── examples/                  # Usage examples
├── scripts/                   # Installation scripts
├── docs/                      # Documentation
├── deep_eye.py               # Main entry point
├── setup.py                  # Package setup
└── requirements.txt          # Dependencies
```

For detailed structure, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## � Troubleshooting

### PDF Report Generation

**Issue**: PDF generation errors on Windows (WeasyPrint library issues)

**Solution**: The tool now uses ReportLab (Windows-friendly) for PDF generation by default. If you encounter any issues:

1. Ensure ReportLab is installed:
```bash
pip install reportlab>=4.0.0
```

2. If PDF generation fails, the tool will automatically fall back to HTML format.

3. For advanced HTML-to-PDF conversion (optional), you can install additional tools, but it's not required.

### Common Issues

**AI Provider Connection Errors**
- Verify your API keys in `config/config.yaml`
- Check your internet connection
- Ensure API key has sufficient credits

**Scanning Errors**
- Verify target URL is accessible
- Check if target has rate limiting or WAF
- Try reducing thread count with `-t` option

## �🛡️ Legal Disclaimer

**IMPORTANT**: Deep Eye is designed for authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with all applicable laws
- The developers assume no liability for misuse

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## � Documentation

- **[Quick Start Guide](docs/QUICKSTART.md)** - Get started quickly
- **[Architecture](docs/ARCHITECTURE.md)** - System design and structure
- **[Testing Guide](docs/TESTING_GUIDE.md)** - Testing procedures
- **[Recon Bridge Runbook](docs/recon-bridge-runbook.md)** - Operating the Shadowbroker bridge integration (v1.4.0)
- **[Contributing](docs/CONTRIBUTING.md)** - How to contribute
- **[Changelog](docs/CHANGELOG.md)** - Version history

## �🙏 Acknowledgments

- OpenAI for GPT models
- Anthropic for Claude
- OWASP for security testing methodologies
- The security research community

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**⚠️ Use Responsibly | 🔒 Test Ethically | 💡 Learn Continuously**
