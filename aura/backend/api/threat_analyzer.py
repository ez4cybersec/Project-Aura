import pandas as pd
import urllib.parse
import re
from tqdm import tqdm

# Import BERT Predictor
try:
    from .bert_predictor import predict_url_attack, predict_url_spoofing
except ImportError:
    from bert_predictor import predict_url_attack, predict_url_spoofing

# ==============================================================================
#  1. REGEX PATTERNS (Standard Signatures)
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

URL_SPOOF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"https?://[^/\s]*@[^/\s]+",
    r"xn--[a-z0-9\-]+",
    r"https?://[a-z0-9\-]{25,}\.(com|net|org)",
    r"(paypa1|paypai|paaypal)\.com",
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
    2. AI Prompt (Spoofing)
    3. AI Check (Split & Predict)
    """
    url = str(row.get('URL', '') or "").strip()
    body = str(row.get('POST_Body', '') or "").strip()

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

    # Specific Checks
    if RFI_PATTERN.search(decoded_url):
        return "Remote File Inclusion (RFI)", "Regex found remote protocol"
    
    if "xml" in full_payload:
        res = check(XXE_PATTERNS, "XXE")
        if res: return res

    # 4. URL Spoofing (Regex Check)
    for p in URL_SPOOF_PATTERNS:
        if p.search(url):
             return "URL Spoofing / Typosquatting", f"Suspicious domain pattern: '{p.pattern}'"

    # 5. HPP Check
    try:
        query = urllib.parse.urlparse(url).query
        if query:
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            for key, val in params.items():
                if len(val) > 1:
                    return "HPP (HTTP Parameter Pollution)", f"Duplicate parameter key: '{key}'"
    except:
        pass

    # --- PHASE 2: AI SPOOFING CHECK (The Prompt) ---
    # If Regex didn't catch spoofing, ask AI specifically about it
    is_spoof, spoof_evidence = predict_url_spoofing(url)
    if is_spoof:
        return "URL Spoofing / Typosquatting", spoof_evidence

    # --- PHASE 3: AI ATTACK CHECK (The Split) ---
    # If still Benign, run the main attack classification
    bert_label, confidence, evidence = predict_url_attack(row.get('URL', ''))
    
    if bert_label != "Benign":
        return bert_label, evidence

    # --- PHASE 4: FINAL VERDICT ---
    return "Benign", "No threat detected"


def detect_bruteforce_smart(df):
    """
    Detects IPs that hit auth endpoints too fast (Time-based) or too frequently (Volume-based).
    Auto-detects if 'Timestamp' column exists.
    """
    # 1. Filter for Authentication URLs (Login, Signin, Admin, etc.)
    auth_patterns = r"login|signin|auth|admin|session|account"
    auth_mask = df['URL'].str.contains(auth_patterns, case=False, na=False)
    auth_df = df[auth_mask].copy()
    
    if auth_df.empty:
        return []

    suspect_ips = []

    # --- METHOD A: Time-Based (Preferred) ---
    if 'Timestamp' in df.columns:
        print("⏱️ Timestamp found. Running Time-Window Analysis...")
        try:
            # Ensure proper datetime format
            auth_df['Timestamp'] = pd.to_datetime(auth_df['Timestamp'])
            
            # Sort is crucial for diff()
            auth_df = auth_df.sort_values(by=['Source_IP', 'Timestamp'])
            
            # Calculate time gap between requests from SAME IP
            auth_df['time_diff'] = auth_df.groupby('Source_IP')['Timestamp'].diff().dt.total_seconds()
            
            # Attack Logic: < 2.0 seconds between auth requests is inhuman
            rapid_fire_mask = auth_df['time_diff'] < 2.0
            suspect_ips = auth_df[rapid_fire_mask]['Source_IP'].unique()
            return suspect_ips
        except Exception as e:
            print(f"⚠️ Timestamp analysis failed ({e}). Falling back to volume count.")
    
    # --- METHOD B: Volume-Based (Fallback) ---
    print("📊 Running Volume-Based Analysis (Fallback)...")
    # Count hits per IP on specific auth URLs
    # We group by IP AND URL to avoid flagging users just browsing around
    grouped = auth_df.groupby(['Source_IP', 'URL']).size().reset_index(name='count')
    
    # Threshold: > 10 hits to the EXACT SAME login URL
    attackers = grouped[grouped['count'] > 10]
    suspect_ips = attackers['Source_IP'].unique()
    
    return suspect_ips


def run_full_analysis(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        df['attack_type'] = []
        df['evidence'] = []
        return df

    df = df.fillna("")
    print("🚀 Starting Hybrid Analysis...")
    tqdm.pandas(desc="Scanning")
    
    # Run the per-row pipeline (Regex + BERT)
    df[['attack_type', 'evidence']] = df.progress_apply(analyze_threats, axis=1, result_type='expand')

    # --- PHASE 3: SMART BRUTEFORCE DETECTION ---
    print("🔎 Checking for Brute Force...")
    
    # Get list of attacking IPs
    attacker_ips = detect_bruteforce_smart(df)
    
    if len(attacker_ips) > 0:
        # Identify rows that belong to these IPs AND match login patterns
        # We don't want to flag *every* request from them, just the login attempts
        auth_pattern = r"login|signin|auth|admin|session|account"
        
        mask = (df['Source_IP'].isin(attacker_ips)) & \
               (df['URL'].str.contains(auth_pattern, case=False, na=False))
        
        # Only overwrite if the row was previously considered Benign
        # (We don't want to overwrite a detected SQL Injection with "Brute Force")
        final_mask = mask & (df['attack_type'] == 'Benign')
        
        if final_mask.any():
            print(f"⚠️ Detected {final_mask.sum()} Brute Force attempts.")
            df.loc[final_mask, 'attack_type'] = "Bruteforce Attack"
            df.loc[final_mask, 'evidence'] = "High frequency/volume authentication requests"

    return df