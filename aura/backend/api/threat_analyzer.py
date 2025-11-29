import pandas as pd
import urllib.parse
import re
from tqdm import tqdm

# ============================
# 1. Pre-Compiled Regex
# (COPIED exactly, don't remove anything)
# ============================

CMD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:;|\||&|&&|\n)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|nc|net|ping|sleep|echo|python|perl|ruby|bash|sh|java|gcc|tar|nslookup)",
    r"/bin/(sh|bash|zsh|dash|ksh)",
    r"(fsockopen|pfsockopen|stream_socket_client|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
    r"cmd\.exe", r"powershell",
    r"\$\(.*\)", r"`.*`",
    r"{{.*system.*}}"
]]

SQLI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"union\s+(all\s+)?select",
    r"select\s+.*\s+from",
    r"(insert\s+into|update\s+.*set|delete\s+from|drop\s+table|alter\s+table|truncate\s+table)",
    r"information_schema|sysobjects|xp_cmdshell",
    r"(or|and)\s+\d+=\d+",
    r"(or|and)\s+['\"][^'\"]+['\"]=['\"][^'\"]+['\"]",
    r"['\"]\s*(or|and)\s*['\"]",
    r"--|/\*|#"
]]

XSS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<script.*?>",
    r"javascript:",
    r"vbscript:",
    r"(alert|confirm|prompt)\s*\(",
    r"on(error|load|mouseover|click|focus|blur|change|submit)\s*=",
    r"<img\s+src",
    r"<iframe",
    r"<svg",
    r"<body"
]]

LFI_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\.\./", r"\.\.\\", r"\.\.%2f",
    r"/etc/(passwd|shadow|issue|group|hosts|motd)",
    r"[c-z]:\\(windows|winnt|boot\.ini)",
    r"php://(filter|input|expect)",
    r"file://"
]]

SSRF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"http://127\.0\.0\.1",
    r"http://localhost",
    r"http://0\.0\.0\.0",
    r"http://169\.254\.169\.254",
    r"http://192\.168\.",
    r"http://10\.",
    r"http://172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"dict://", r"gopher://", r"ldap://"
]]

XXE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<!entity", r"<!doctype", r"system\s+[\"']", r"public\s+[\"']"
]]

# NEW: URL Spoofing / Typosquatting patterns
URL_SPOOF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    # Use of @ in URL: http://legit.com@evil.com
    r"https?://[^/\s]*@[^/\s]+",

    # Punycode domains (can be used for homograph attacks)
    r"xn--[a-z0-9\-]+",

    # Very long suspicious-looking domains (many chars before main TLD)
    r"https?://[a-z0-9\-]{25,}\.(com|net|org|xyz|top|info)",

    # Common brand typos (examples – you can add more)
    r"(paypa1|paypai|paaypal)\.com",
    r"(g00gle|goog1e)\.com",
    r"(faceb00k|facbook)\.com",
    r"(micros0ft|rnicrosoft)\.com",
    r"(instaqram|lnstagram)\.com",
    r"(linkedln|1inkedin)\.com"
]]

# NEW: Shell upload patterns (web shells, malicious scripts)
SHELL_UPLOAD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    # filename="shell.php", filename=shell.asp, etc. in URL or body
    r"filename\s*=\s*\"?[^\"]*\.(php[0-9]?|phtml|pht|phar|asp|aspx|jsp|cfm|cgi|pl|sh|bash)\"?",

    # Generic "shell" filename indicators
    r"(web)?shell\.php",
    r"(c99|r57|b374k)\.php",

    # Sometimes content-type reveals php upload
    r"content-type\s*:\s*application/(x-php|x-httpd-php|x-shellscript)"
]]


RFI_PATTERN = re.compile(r"=\s*(http|https|ftp|ftps)://", re.IGNORECASE)


def analyze_threats(row):
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

    if any(p.search(full) for p in CMD_PATTERNS):
        return "Command Injection"

    if any(p.search(full) for p in SQLI_PATTERNS):
        return "SQL Injection"

    if any(p.search(full) for p in XSS_PATTERNS):
        return "Cross-Site Scripting (XSS)"
    
    if any(p.search(decoded_url) or p.search(spoof_surface) for p in URL_SPOOF_PATTERNS):
        return "URL Spoofing / Typosquatting"

    if any(p.search(full) for p in LFI_PATTERNS):
        return "Directory Traversal / LFI"

    if any(p.search(full) for p in SSRF_PATTERNS):
        return "SSRF"

    if "xml" in full and any(p.search(full) for p in XXE_PATTERNS):
        return "XXE"

    if RFI_PATTERN.search(decoded_url):
        return "Remote File Inclusion (RFI)"

    upload_surface = full
    if any(p.search(upload_surface) for p in SHELL_UPLOAD_PATTERNS):
        return "Shell Upload Attempt"

    # ---------- H. HTTP Parameter Pollution ----------
    try:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        if any(len(v) > 1 for v in params.values()):
            return "HPP (HTTP Parameter Pollution)"
    except:
        pass

    return "Benign"


def run_full_analysis(df: pd.DataFrame) -> pd.DataFrame:
    """Apply regex detection + bruteforce logic to a dataframe and return it."""
    df = df.fillna("")
    tqdm.pandas()
    df['attack_type'] = df.progress_apply(analyze_threats, axis=1)

    # Bruteforce detection
    login_df = df[df['URL'].str.contains("login", case=False, na=False)]
    if not login_df.empty:
        brute_counts = login_df.groupby(['Source_IP']).URL.transform('count')
        df.loc[
            login_df.index[(brute_counts >= 5) & (df.loc[login_df.index, 'attack_type'] == 'Benign')],
            'attack_type'
        ] = "Bruteforce Attack"

    return df
