import pandas as pd
import urllib.parse
import re
from tqdm import tqdm

# Import the BERT predictor
# This file handles the "Split URL" and "Validation" logic you requested
try:
    from .bert_predictor import predict_url_attack
except ImportError:
    from bert_predictor import predict_url_attack

# ==============================================================================
#  1. REGEX PATTERNS (Known Signatures)
# ==============================================================================

CMD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:;|\||\|\||&&|\n|\$\()\s*\b(ls|cat|pwd|whoami|id|uname|wget|curl|nc|net|ping|sleep|echo|python|perl|ruby|bash|sh|java|gcc|tar|nslookup)\b",
    r"/bin/(sh|bash|zsh|dash|ksh)",
    r"\b(fsockopen|pfsockopen|stream_socket_client|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
    r"cmd\.exe", r"powershell",
    r"\$\(.*\)", r"`.*`",
    r"{{.*system.*}}"
]]

SQLI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"union\s+(all\s+)?select",
    r"\bselect\s+.*?\s+from\b",
    r"\b(insert\s+into|update\s+.*?set|delete\s+from|drop\s+table|alter\s+table|truncate\s+table)\b",
    r"information_schema|sysobjects|xp_cmdshell",
    r"(or|and)\s+\d+=\d+",
    r"(or|and)\s+['\"][^'\"]+['\"]=['\"][^'\"]+['\"]",
    r"['\"]\s*(or|and)\s*['\"]",
    r"--|/\*|#"
]]

XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<script.*?>", r"javascript:", r"vbscript:",
    r"(alert|confirm|prompt)\s*\(",
    r"on(error|load|mouseover|click|focus|blur|change|submit)\s*=",
    r"<img\s+src", r"<iframe", r"<svg", r"<body"
]]

LFI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\.\./", r"\.\.\\", r"\.\.%2f",
    r"/etc/(passwd|shadow|issue|group|hosts|motd)",
    r"[c-z]:\\(windows|winnt|boot\.ini)",
    r"php://(filter|input|expect)",
    r"file://"
]]

SSRF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"=\s*http://127\.0\.0\.1", r"=\s*http://localhost",
    r"=\s*http://0\.0\.0\.0", r"=\s*http://169\.254\.169\.254",
    r"=\s*http://192\.168\.", r"=\s*http://10\.",
    r"=\s*http://172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"dict://", r"gopher://", r"ldap://"
]]

XXE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<!entity", r"<!doctype", r"system\s+[\"']", r"public\s+[\"']"
]]

# Includes Typosquatting & Spoofing (e.g. @ redirect, punycode, fake brands)
URL_SPOOF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"https?://[^/\s]*@[^/\s]+",                  # @ redirection (google.com@evil.com)
    r"xn--[a-z0-9\-]+",                            # Punycode (homograph attacks)
    r"https?://[a-z0-9\-]{25,}\.(com|net|org)",    # Suspiciously long domains
    r"(paypa1|paypai|paaypal)\.com",               # Brand Spoofing
    r"(g00gle|goog1e|gooogle)\.com",
    r"(faceb00k|facbook)\.com",
    r"(micros0ft|rnicrosoft)\.com",
    r"(instaqram|lnstagram)\.com",
    r"(linkedln|1inkedin)\.com"
]]

SHELL_UPLOAD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"filename\s*=\s*\"?[^\"]*\.(php[0-9]?|phtml|pht|phar|asp|aspx|jsp|cfm|cgi|pl|sh|bash)\"?",
    r"(web)?shell\.php",
    r"(c99|r57|b374k)\.php",
    r"content-type\s*:\s*application/(x-php|x-httpd-php|x-shellscript)"
]]

RFI_PATTERN = re.compile(r"=\s*(http|https|ftp|ftps)://", re.IGNORECASE)


# ==============================================================================
#  2. MAIN ANALYSIS PIPELINE
# ==============================================================================

def analyze_threats(row):
    """
    Pipeline: 
    1. Regex (Standard + Spoofing) 
    2. If Benign -> AI Check (Split & Predict handled in bert_predictor)
    """
    url = str(row.get('URL', '') or "").strip()
    body = str(row.get('POST_Body', '') or "").strip()

    # Normalize URL
    try:
        decoded_url = urllib.parse.unquote_plus(url).lower()
    except:
        decoded_url = url.lower()

    body = body.lower()
    full_payload = decoded_url + " " + body
    
    # Helper to check list of patterns
    def check(patterns, name):
        for p in patterns:
            if p.search(full_payload): 
                return name, f"Matched regex pattern: '{p.pattern[:25]}...'"
        return None

    # --- PHASE 1: REGEX CHECKS (The Filter) ---
    
    # 1. Standard Attacks
    checks = [
        (CMD_PATTERNS, "Command Injection"),
        (SQLI_PATTERNS, "SQL Injection"),
        (XSS_PATTERNS, "Cross-Site Scripting (XSS)"),
        (LFI_PATTERNS, "Directory Traversal / LFI"),
        (SSRF_PATTERNS, "SSRF"),
        (SHELL_UPLOAD_PATTERNS, "Shell Upload Attempt")
    ]
    for pats, name in checks:
        res = check(pats, name)
        if res: return res

    # 2. RFI (Specific single regex)
    if RFI_PATTERN.search(decoded_url):
        return "Remote File Inclusion (RFI)", "Regex found remote protocol in parameters"
    
    # 3. XXE
    if "xml" in full_payload:
        res = check(XXE_PATTERNS, "XXE")
        if res: return res

    # 4. URL Spoofing / Typosquatting (This was missing in your snippet!)
    # We check the RAW url for domains, not the decoded payload
    for p in URL_SPOOF_PATTERNS:
        if p.search(url):
             return "URL Spoofing / Typosquatting", f"Suspicious domain pattern: '{p.pattern}'"

    # 5. HTTP Parameter Pollution (HPP)
    try:
        query = urllib.parse.urlparse(url).query
        if query:
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            for key, val in params.items():
                if len(val) > 1:
                    return "HPP (HTTP Parameter Pollution)", f"Duplicate parameter key: '{key}'"
    except:
        pass

    # --- PHASE 2: AI CHECK (BERT) ---
    # If we are here, Regex returned "Benign".
    # We pass the FULL URL. The 'bert_predictor' script handles the splitting 
    # (Base vs Query) and the "Is this really an attack?" validation logic.
    
    bert_label, confidence, evidence = predict_url_attack(row.get('URL', ''))
    
    if bert_label != "Benign":
        return bert_label, evidence

    # --- FINAL VERDICT ---
    return "Benign", "No threat detected"


def run_full_analysis(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        df['attack_type'] = []
        df['evidence'] = []
        return df

    df = df.fillna("")
    print("🚀 Starting Hybrid Analysis (Regex + AI)...")
    tqdm.pandas(desc="Scanning")
    
    # Apply pipeline per row
    df[['attack_type', 'evidence']] = df.progress_apply(analyze_threats, axis=1, result_type='expand')

    # --- PHASE 3: BRUTEFORCE DETECTION ---
    # Traffic volume analysis (Post-Processing)
    login_mask = df['URL'].str.contains("login", case=False, na=False)
    
    if login_mask.any():
        brute_counts = df[login_mask].groupby('Source_IP')['URL'].transform('count')
        
        # Only mark as Brute Force if it wasn't already caught as something else
        potential_brute = (brute_counts >= 5) & (df.loc[login_mask.index, 'attack_type'] == 'Benign')
        target_indices = login_mask.index[potential_brute]
        
        if not target_indices.empty:
            df.loc[target_indices, 'attack_type'] = "Bruteforce Attack"
            df.loc[target_indices, 'evidence'] = "High frequency login attempts (5+ from single IP)"

    return df