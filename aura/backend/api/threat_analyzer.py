import pandas as pd
import urllib.parse
import re
from tqdm import tqdm

# ==============================================================================
#  1. FIXED REGEX PATTERNS (Existing patterns kept exactly as is)
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
    r"https?://[a-z0-9\-]{25,}\.(com|net|org|xyz|top|info)",
    r"(paypa1|paypai|paaypal)\.com",
    r"(g00gle|goog1e)\.com",
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
#  2. ANALYSIS LOGIC (UPDATED WITH EVIDENCE EXTRACTION)
# ==============================================================================

def analyze_threats(row):
    """
    Returns a tuple: (Attack_Type_String, Evidence_String)
    """
    url = str(row.get('URL', '') or "").strip()
    body = str(row.get('POST_Body', '') or "").strip()

    try:
        decoded_url = urllib.parse.unquote_plus(url).lower()
    except Exception:
        decoded_url = url.lower()

    body = body.lower()
    full = decoded_url + " " + body
    
    parsed = urllib.parse.urlparse(decoded_url)
    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    spoof_surface = host + path

    # --- HELPER FUNCTION FOR EVIDENCE ---
    def find_match(patterns, threat_name):
        for p in patterns:
            match = p.search(full)
            if match:
                # Return tuple: (Type, Evidence)
                return threat_name, f"Matched pattern: '{match.group(0)}'"
        return None

    # --- CHECKS ---

    # 1. Command Injection
    res = find_match(CMD_PATTERNS, "Command Injection")
    if res: return res

    # 2. SQL Injection
    res = find_match(SQLI_PATTERNS, "SQL Injection")
    if res: return res

    # 3. XSS
    res = find_match(XSS_PATTERNS, "Cross-Site Scripting (XSS)")
    if res: return res
    
    # 4. URL Spoofing (Special case: check specific surfaces)
    for p in URL_SPOOF_PATTERNS:
        if p.search(decoded_url) or p.search(spoof_surface):
             return "URL Spoofing / Typosquatting", f"Suspicious domain pattern: '{p.pattern}'"

    # 5. LFI
    res = find_match(LFI_PATTERNS, "Directory Traversal / LFI")
    if res: return res

    # 6. SSRF
    res = find_match(SSRF_PATTERNS, "SSRF")
    if res: return res

    # 7. XXE
    if "xml" in full:
        res = find_match(XXE_PATTERNS, "XXE")
        if res: return res

    # 8. RFI
    match = RFI_PATTERN.search(decoded_url)
    if match:
        return "Remote File Inclusion (RFI)", f"Remote inclusion pattern: '{match.group(0)}'"

    # 9. Shell Upload
    res = find_match(SHELL_UPLOAD_PATTERNS, "Shell Upload Attempt")
    if res: return res

    # 10. HPP
    try:
        query = urllib.parse.urlparse(url).query
        if query:
            params = urllib.parse.parse_qs(query, keep_blank_values=True)
            for key, val in params.items():
                if len(val) > 1:
                    return "HPP (HTTP Parameter Pollution)", f"Duplicate parameter key: '{key}'"
    except Exception:
        pass

    return "Benign", "No specific threat pattern detected"


def run_full_analysis(df: pd.DataFrame) -> pd.DataFrame:
    """Apply regex detection + bruteforce logic to a dataframe and return it."""
    if df.empty:
        df['attack_type'] = []
        df['evidence'] = []
        return df

    df = df.fillna("")
    tqdm.pandas(desc="Analyzing Threats")
    
    # KEY CHANGE: result_type='expand' splits the returned tuple into two columns
    df[['attack_type', 'evidence']] = df.progress_apply(analyze_threats, axis=1, result_type='expand')

    # Bruteforce detection
    login_mask = df['URL'].str.contains("login", case=False, na=False)
    
    if login_mask.any():
        brute_counts = df[login_mask].groupby('Source_IP')['URL'].transform('count')
        potential_brute_indices = df[login_mask].index
        conditions = (brute_counts >= 5) & (df.loc[potential_brute_indices, 'attack_type'] == 'Benign')
        target_indices = potential_brute_indices[conditions]
        
        # Update Type AND Evidence
        df.loc[target_indices, 'attack_type'] = "Bruteforce Attack"
        df.loc[target_indices, 'evidence'] = "High frequency login attempts (5+ from single IP)"

    return df