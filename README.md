# 🔐 SecureScan AI

[![CI Tests](https://github.com/saimani21/securescan-ai-v2/actions/workflows/ci-tests.yml/badge.svg)](https://github.com/saimani21/securescan-ai-v2/actions/workflows/ci-tests.yml)
[![Security Scan](https://github.com/saimani21/securescan-ai-v2/actions/workflows/security-scan.yml/badge.svg)](https://github.com/saimani21/securescan-ai-v2/actions/workflows/security-scan.yml)
[![codecov](https://codecov.io/gh/saimani21/securescan-ai-v2/branch/main/graph/badge.svg)](https://codecov.io/gh/saimani21/securescan-ai-v2)

---

### 🧠 AI-Powered Security Code Review Tool

SecureScan AI is an advanced static code analysis and vulnerability scanner with the following features:

- 🔍 **Semgrep-based engine** for code pattern detection
- 🕵️‍♂️ **Secrets detection** (20+ regex patterns)
- 🤖 **AI validation** with OpenAI GPT-4o
- 📦 **CVE/CWE enrichment** using NVD + CISA KEV
- ⚠️ **CVSS scoring**, threat classification
- 📂 Output formats: JSON, SARIF, Console
- 🧪 CLI tool + GitHub Actions CI support

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/saimani21/securescan-ai-v2.git
cd securescan-ai-v2

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements/base.txt
pip install .

# Run a scan
secscan scan src/securescan --severity HIGH --severity CRITICAL
