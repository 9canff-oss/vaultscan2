# vaultscan2
AI-powered web security scanner — DNS, headers, tech detection &amp; security reports


# 🔍 VaultScan — AI Security Intelligence

VaultScan is a real-time web security scanner that analyzes 
any website URL and generates a comprehensive security report.

## Features
- 🌐 Real DNS Analysis (A, MX, NS, SPF, DMARC, DNSSEC)
- 🔬 Technology Detection (30+ frameworks & tools)
- 📊 Security Headers Analysis (OWASP mapped)
- 🤖 AI-written Security Intelligence Report
- 📈 Security Score (0-100) with Grade

## Tech Stack
- Backend: Python FastAPI
- AI: NVIDIA NIM (Llama 3.1)
- Frontend: HTML, CSS, JavaScript

## Setup
1. Install dependencies:
   pip install fastapi uvicorn python-whois dnspython httpx beautifulsoup4

2. Set API key:
   set NVIDIA_API_KEY=your_key_here

3. Run backend:
   python -m uvicorn main:app --reload --port 8000

4. Open frontend/index.html in browser

## ⚠️ Legal Notice
Only scan websites you own or have explicit permission to test.
