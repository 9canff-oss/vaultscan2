"""
VaultScan Backend — FastAPI + NVIDIA NIM AI
"""
import asyncio, json, os, re, time
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import httpx
import whois
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="VaultScan API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

class ScanRequest(BaseModel):
    url: str

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://","https://")): url = "https://" + url
    return url

def extract_domain(url):
    return urlparse(url).netloc or url

async def analyze_dns(domain):
    result = {"a_records":[],"mx_records":[],"ns_records":[],"spf":None,"dmarc":None,"dnssec":False,"issues":[],"info":[]}
    r = dns.resolver.Resolver(); r.timeout = 5; r.lifetime = 5
    try:
        ans = r.resolve(domain, "A"); result["a_records"] = [str(x) for x in ans]
        result["info"].append(f"Resolves to: {', '.join(result['a_records'][:3])}")
    except: result["issues"].append("Domain does not resolve")
    try:
        ans = r.resolve(domain, "MX"); result["mx_records"] = [str(x.exchange) for x in ans]
    except: pass
    try:
        ans = r.resolve(domain, "NS"); result["ns_records"] = [str(x) for x in ans]
    except: pass
    try:
        ans = r.resolve(domain, "TXT")
        for rd in ans:
            t = str(rd).strip('"')
            if t.startswith("v=spf1"): result["spf"] = t
        if not result["spf"]: result["issues"].append("Missing SPF record — email spoofing possible")
    except: result["issues"].append("Could not retrieve TXT records")
    try:
        ans = r.resolve(f"_dmarc.{domain}", "TXT")
        for rd in ans:
            t = str(rd).strip('"')
            if t.startswith("v=DMARC1"): result["dmarc"] = t
        if not result["dmarc"]: result["issues"].append("Missing DMARC record — phishing risk")
    except: result["issues"].append("Missing DMARC record — phishing risk")
    try: r.resolve(domain,"DS"); result["dnssec"]=True
    except: result["issues"].append("DNSSEC not enabled")
    return result

async def analyze_whois(domain):
    result = {"registrar":None,"creation_date":None,"expiration_date":None,"domain_age_days":None,"expires_in_days":None,"privacy_protected":False,"name_servers":[],"issues":[],"info":[]}
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        result["registrar"] = str(w.registrar) if w.registrar else None
        cd = w.creation_date
        if isinstance(cd,list): cd=cd[0]
        if cd and hasattr(cd,"strftime"):
            result["creation_date"] = cd.strftime("%Y-%m-%d")
            age = (datetime.now()-cd).days; result["domain_age_days"] = age
            if age<180: result["issues"].append(f"Domain only {age} days old — higher risk")
            else: result["info"].append(f"Domain age: {age//365} year(s)")
        ed = w.expiration_date
        if isinstance(ed,list): ed=ed[0]
        if ed and hasattr(ed,"strftime"):
            result["expiration_date"] = ed.strftime("%Y-%m-%d")
            exp = (ed-datetime.now()).days; result["expires_in_days"] = exp
            if exp<30: result["issues"].append(f"Domain expires in {exp} days!")
        if w.name_servers: result["name_servers"] = [str(ns).lower() for ns in w.name_servers]
        if any(k in str(w).lower() for k in ["privacy","redacted","protected"]): result["privacy_protected"]=True
    except Exception as e: pass
    return result

TECH_SIGS = {
    "WordPress": {"h":[],"html":["wp-content","wp-includes"]},
    "Shopify": {"h":["x-shopid"],"html":["cdn.shopify.com"]},
    "Wix": {"h":[],"html":["wixstatic.com"]},
    "React": {"h":[],"html":["data-reactroot","__NEXT_DATA__","_reactFiber"]},
    "Next.js": {"h":["x-powered-by: next.js"],"html":["__NEXT_DATA__","_next/static"]},
    "Vue.js": {"h":[],"html":["vue-router","data-v-"]},
    "Angular": {"h":[],"html":["ng-version","ng-app"]},
    "PHP": {"h":["x-powered-by: php"],"html":[]},
    "ASP.NET": {"h":["x-powered-by: asp.net"],"html":["__VIEWSTATE"]},
    "Cloudflare": {"h":["cf-ray","server: cloudflare"],"html":[]},
    "Nginx": {"h":["server: nginx"],"html":[]},
    "Apache": {"h":["server: apache"],"html":[]},
    "Google Analytics": {"h":[],"html":["gtag(","google-analytics.com"]},
    "Google Tag Manager": {"h":[],"html":["googletagmanager.com"]},
}
TECH_CAT = {"WordPress":"CMS","Shopify":"CMS","Wix":"CMS","React":"JS Framework","Next.js":"JS Framework","Vue.js":"JS Framework","Angular":"JS Framework","PHP":"Backend","ASP.NET":"Backend","Cloudflare":"CDN","Nginx":"Server","Apache":"Server","Google Analytics":"Analytics","Google Tag Manager":"Analytics"}

async def detect_technologies(url, html, headers):
    detected=[]; issues=[]; hl=html.lower(); hs=" ".join(f"{k}: {v}" for k,v in headers.items()).lower()
    for tech,sigs in TECH_SIGS.items():
        if any(h.lower() in hs for h in sigs["h"]) or any(h.lower() in hl for h in sigs["html"]):
            detected.append({"name":tech,"category":TECH_CAT.get(tech,"Other")})
    m = re.search(r'jquery[.-](\d+\.\d+)',hl)
    if m:
        v=m.group(1); out=int(v.split(".")[0])<3
        detected.append({"name":f"jQuery {v}","category":"JS Library","outdated":out})
        if out: issues.append(f"jQuery {v} is outdated — known CVEs exist")
    return {"technologies":detected,"issues":issues}

SEC_HDRS = {
    "Strict-Transport-Security":("high","Missing HSTS — HTTP downgrade possible","Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy":("high","Missing CSP — XSS attacks possible","Define Content-Security-Policy header"),
    "X-Frame-Options":("medium","Missing X-Frame-Options — clickjacking risk","Add: X-Frame-Options: DENY"),
    "X-Content-Type-Options":("medium","Missing X-Content-Type-Options — MIME sniffing","Add: X-Content-Type-Options: nosniff"),
    "Referrer-Policy":("low","Missing Referrer-Policy","Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy":("low","Missing Permissions-Policy","Add: Permissions-Policy: camera=(), microphone=()"),
}

def analyze_headers(headers):
    hl={k.lower():v for k,v in headers.items()}; findings=[]
    for hdr,(sev,desc,fix) in SEC_HDRS.items():
        if hdr.lower() not in hl:
            findings.append({"title":f"Missing {hdr}","subtitle":hdr,"severity":sev,"description":desc,"evidence":f"Header '{hdr}' absent","remediation":fix,"category":"Security Headers"})
    sv=hl.get("server","")
    if sv and any(v in sv.lower() for v in ["apache/","nginx/","iis/","php/"]):
        findings.append({"title":"Server Version Disclosure","subtitle":f"Server: {sv}","severity":"medium","description":f"Server header reveals version: {sv}","evidence":f"Server: {sv}","remediation":"Hide version info in server config","category":"Info Disclosure"})
    xpb=hl.get("x-powered-by","")
    if xpb: findings.append({"title":"Technology Disclosure","subtitle":f"X-Powered-By: {xpb}","severity":"low","description":f"X-Powered-By reveals backend: {xpb}","evidence":f"X-Powered-By: {xpb}","remediation":"Remove X-Powered-By header","category":"Info Disclosure"})
    return {"findings":findings}

def map_owasp(hf, di, ti):
    s=" ".join([f["title"] for f in hf]+di+ti).lower()
    def st(fk,wk=None): return "fail" if any(k in s for k in fk) else "warn" if wk and any(k in s for k in wk) else "pass"
    return [
        {"id":"A01","name":"Broken Access Control","status":st(["access control"])},
        {"id":"A02","name":"Cryptographic Failures","status":st(["hsts","ssl","tls"])},
        {"id":"A03","name":"Injection","status":st(["xss","injection"],["csp"])},
        {"id":"A04","name":"Insecure Design","status":st([],["missing"])},
        {"id":"A05","name":"Security Misconfiguration","status":st(["disclosure","x-powered-by"],["missing"])},
        {"id":"A06","name":"Vulnerable Components","status":st(["outdated","cve"])},
        {"id":"A07","name":"Auth Failures","status":st(["authentication"])},
        {"id":"A08","name":"Data Integrity Failures","status":st(["dmarc","spf"])},
        {"id":"A09","name":"Logging Failures","status":st(["logging"])},
        {"id":"A10","name":"SSRF","status":st(["ssrf"])},
    ]

async def get_ai_analysis(url, findings, dns_data, whois_data, tech_data):
    if not NVIDIA_API_KEY: return "AI analysis unavailable — set NVIDIA_API_KEY"
    summary = {"url":url,"dns_issues":dns_data.get("issues",[]),"technologies":[t["name"] for t in tech_data.get("technologies",[])],"findings":[{"title":f["title"],"severity":f["severity"]} for f in findings]}
    prompt = f"""You are a senior penetration tester writing a security report.
Target: {url}
Data: {json.dumps(summary)}
Write 3 paragraphs: 1) Overall risk and critical issues 2) Attack surface observations 3) Remediation roadmap. Prose only."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(f"{NVIDIA_BASE_URL}/chat/completions",
                headers={"Authorization":f"Bearer {NVIDIA_API_KEY}","Content-Type":"application/json"},
                json={"model":"meta/llama-3.1-8b-instruct","messages":[{"role":"user","content":prompt}],"max_tokens":600,"temperature":0.7})
            return r.json()["choices"][0]["message"]["content"]
    except Exception as e: return f"AI analysis failed: {str(e)[:100]}"

def calc_score(findings):
    d={"critical":25,"high":15,"medium":8,"low":3,"info":0}
    sc=max(0,100-sum(d.get(f.get("severity","info"),0) for f in findings))
    gr="A" if sc>=90 else "B" if sc>=75 else "C" if sc>=60 else "D" if sc>=40 else "F"
    return sc,gr

@app.post("/scan")
async def scan(req: ScanRequest):
    url=normalize_url(req.url); domain=extract_domain(url)
    if not domain: raise HTTPException(400,"Invalid URL")
    start=time.time(); html=""; hdrs={}
    try:
        async with httpx.AsyncClient(timeout=10,follow_redirects=True,headers={"User-Agent":"Mozilla/5.0 (VaultScan/1.0)"}) as c:
            r=await c.get(url); html=r.text; hdrs=dict(r.headers)
    except: pass
    dns_data,whois_data = await asyncio.gather(analyze_dns(domain),analyze_whois(domain))
    tech_data=await detect_technologies(url,html,hdrs)
    hdr_data=analyze_headers(hdrs)
    findings=list(hdr_data["findings"])
    for i in dns_data["issues"]: findings.append({"title":i,"subtitle":"DNS","severity":"medium" if any(k in i.lower() for k in ["spf","dmarc"]) else "low","description":i,"evidence":f"DNS: {domain}","remediation":"Fix DNS records","category":"DNS"})
    for i in whois_data["issues"]: findings.append({"title":i,"subtitle":"WHOIS","severity":"medium","description":i,"evidence":f"WHOIS: {domain}","remediation":"Update domain registration","category":"Domain"})
    for i in tech_data["issues"]: findings.append({"title":i,"subtitle":"Outdated Component","severity":"high","description":i,"evidence":"HTML fingerprinting","remediation":"Update to latest version","category":"Components"})
    score,grade=calc_score(findings)
    owasp=map_owasp(hdr_data["findings"],dns_data["issues"],tech_data["issues"])
    stats={"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings: stats[f.get("severity","info")]=stats.get(f.get("severity","info"),0)+1
    ai=await get_ai_analysis(url,findings,dns_data,whois_data,tech_data)
    elapsed=round(time.time()-start,2)
    return {"score":score,"grade":grade,"summary":f"Found {len(findings)} issues in {elapsed}s.","elapsed":elapsed,"domain":domain,"stats":stats,"owasp":owasp,"findings":findings,"dns":{"records":{"A":dns_data["a_records"],"MX":dns_data["mx_records"],"NS":dns_data["ns_records"]},"spf":dns_data["spf"],"dmarc":dns_data["dmarc"],"dnssec":dns_data["dnssec"],"info":dns_data["info"]},"whois":{"registrar":whois_data["registrar"],"creation_date":whois_data["creation_date"],"expiration_date":whois_data["expiration_date"],"domain_age_days":whois_data["domain_age_days"],"expires_in_days":whois_data["expires_in_days"],"name_servers":whois_data["name_servers"],"privacy_protected":whois_data["privacy_protected"],"info":whois_data["info"]},"technologies":tech_data["technologies"],"ai_analysis":ai}

@app.get("/health")
async def health(): return {"status":"ok","version":"1.0.0","ai":"nvidia-nim"}
