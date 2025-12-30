# ASE - Attack Simulation Engine 🛡️

A comprehensive web-based security auditing and vulnerability assessment platform built with Streamlit. ASE provides real-time security scanning, vulnerability detection, and risk assessment for web applications and networks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.28+-red.svg)

## 🌟 Features

### Core Security Features
- **🔍 URL Security Analysis** - Comprehensive web application vulnerability scanning
- **🌐 Network Scanning** - Nmap integration for port and service discovery
- **💉 SQL Injection Detection** - Automated SQLi vulnerability testing
- **🔐 Authentication Analysis** - Security header and authentication mechanism assessment
- **📊 Risk Assessment** - Deterministic 5x5 risk matrix scoring
- **🎯 Attack Simulation** - Passive security analysis and threat modeling

### Advanced Features
- **🤖 AI-Powered Chatbot** - Security recommendations using Google Gemini AI
- **👥 Multi-User Support** - Role-based access control (User/Admin)
- **📈 Interactive Dashboards** - Real-time visualization with Plotly charts
- **📄 Export Reports** - PDF and CSV export capabilities
- **🔒 Social Authentication** - Google, GitHub, and LinkedIn login support
- **🌓 Dark/Light Mode** - Modern UI with glassmorphism effects
- **📝 Audit Logging** - Comprehensive activity tracking

### Security Modules
- JSON Security Analyzer
- OSINT (Open Source Intelligence) Analyzer
- Malware Analysis
- Code Scanner (SAST)
- Brute Force Detection
- API Security Auditor
- Cloud Security Auditor
- Defensive Security Suite
- Intelligence Suite

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- (Optional) Nmap for network scanning

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/ase-security-platform.git
cd ase-security-platform
```

2. **Create a virtual environment**
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API keys
# GEMINI_API_KEY=your_actual_api_key
# ADMIN_ACCESS_CODE=your_secure_admin_code
```

5. **Run the application**
```bash
streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`

## 📖 Usage

### First Time Setup

1. **Create an Account**
   - Click "Sign Up" on the login page
   - Fill in your details
   - (Optional) Use admin code to register as admin

2. **Login**
   - Use email/password or social login
   - Access the main dashboard

3. **Run Your First Scan**
   - Navigate to "URL Security Scanner"
   - Enter a target URL (must own or have permission)
   - Confirm ownership
   - Click "Start Scan"

### Available Scan Types

- **URL Security Scan** - Web application vulnerability assessment
- **Network Scan** - Port scanning and service detection (requires Nmap)
- **JSON Analysis** - API and JSON payload security analysis
- **SQL Injection Test** - Database vulnerability testing
- **Code Analysis** - Static application security testing (SAST)
- **OSINT Analysis** - Open source intelligence gathering
- **Malware Analysis** - File and URL malware detection

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GEMINI_API_KEY` | Google Gemini API key for AI chatbot | No |
| `ADMIN_ACCESS_CODE` | Admin panel access code | Yes |
| `SECRET_KEY` | Session encryption key | No |

### Getting API Keys

**Google Gemini API Key:**
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Add to your `.env` file

## 🏗️ Architecture

```
ase.new/core/
├── app.py                      # Main Streamlit application
├── scanner.py                  # Core scanning orchestration
├── attack_simulator.py         # Security analysis engine
├── url_checker.py              # URL validation and analysis
├── risk_model.py               # Risk assessment logic
├── models.py                   # Data models
├── auth_manager.py             # Authentication system
├── user_manager.py             # User management
├── session_manager.py          # Session state management
├── nmap_scanner.py             # Network scanning
├── sqli_analyzer.py            # SQL injection testing
├── json_analyzer.py            # JSON security analysis
├── code_scanner.py             # SAST implementation
├── osint_analyzer.py           # OSINT gathering
├── malware_analyzer.py         # Malware detection
├── api_auditor.py              # API security testing
├── report_generator.py         # Report generation
└── requirements.txt            # Python dependencies
```

## 🔒 Security Features

### Input Validation
- Blocked domains (Google, Facebook, etc.)
- Private IP range detection
- URL format validation
- Size limits on inputs

### Data Protection
- Password hashing (SHA-256)
- Session state isolation
- Audit logging
- No sensitive data in logs

### Compliance
- Deterministic risk scoring
- Comprehensive audit trails
- Clear error messages
- Graceful degradation

## 📊 Risk Assessment

ASE uses a standardized **5x5 Risk Matrix**:

```
Likelihood (1-5) × Impact (1-5) = Risk Score (1-25)

16-25 = Critical
9-15  = High
4-8   = Medium
1-3   = Low
```

## 🐛 Troubleshooting

### Common Issues

**"URL unreachable" error**
- Verify target is online
- Try HTTP if HTTPS fails
- Check firewall rules

**"Blocked domain" error**
- Target is in restricted list
- Use a different test target

**"Nmap not available"**
- Install Nmap: `sudo apt-get install nmap` (Linux)
- Download from [nmap.org](https://nmap.org/download.html) (Windows)

**API Key errors**
- Verify `.env` file exists
- Check API key is valid
- Restart the application

## 📝 Documentation

- [FIXES_APPLIED.md](FIXES_APPLIED.md) - Technical implementation details
- [FRONTEND_INTEGRATION.md](FRONTEND_INTEGRATION.md) - Integration guide
- [README_FIXES.md](README_FIXES.md) - Comprehensive fix summary
- [DEPLOYMENT.md](DEPLOYMENT.md) - Deployment instructions

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for **authorized security testing only**. Users must:
- Have explicit permission to scan targets
- Comply with local laws and regulations
- Use responsibly and ethically

Unauthorized scanning may be illegal. The developers are not responsible for misuse.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Powered by [Google Gemini AI](https://ai.google.dev/)
- Network scanning via [Nmap](https://nmap.org/)
- Charts by [Plotly](https://plotly.com/)

## 📧 Contact

For questions, issues, or suggestions, please open an issue on GitHub.

---

**Made with ❤️ for the security community**
