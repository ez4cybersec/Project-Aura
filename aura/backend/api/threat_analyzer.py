import pandas as pd
import urllib.parse
import re
from tqdm import tqdm

# Import Predictors
try:
    from .bert_predictor import predict_url_attack, predict_url_spoofing
    from .ml_predictor import predict_ml_attack
except ImportError:
    from bert_predictor import predict_url_attack, predict_url_spoofing
    from ml_predictor import predict_ml_attack

# --- REGEX PATTERNS ---
CMD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"(?:;|\||\|\||&&|\n|\$\()\s*\b(ls|cat|pwd|whoami|id|uname|wget|curl|nc|net|ping|sleep|echo|python|perl|ruby|bash|sh|java|gcc|tar|nslookup)\b",
    r"/bin/(sh|bash|zsh|dash|ksh)",
    r"\b(fsockopen|pfsockopen|stream_socket_client|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
    r"cmd\.exe",
    r"powershell",
    r"\$\(.*\)",
    r"`.*`",
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
    r"\.\./",
    r"\.\.\\",
    r"\.\.%2f",
    r"/etc/(passwd|shadow|issue|group|hosts|motd)",
    r"[c-z]:\\(windows|winnt|boot\.ini)",
    r"php://(filter|input|expect)",
    r"file://"
]]

SSRF_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"=\s*http://127\.0\.0\.1",
    r"=\s*http://localhost",
    r"=\s*http://0\.0\.0\.0",
    r"=\s*http://169\.254\.169\.254",
    r"=\s*http://192\.168\.",
    r"=\s*http://10\.",
    r"=\s*http://172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"dict://",
    r"gopher://",
    r"ldap://"
]]

XXE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"<!entity",
    r"<!doctype",
    r"system\s+[\"']",
    r"public\s+[\"']"
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


class PipelineStats:
    def __init__(self):
        self.total = 0
        self.regex = 0
        self.ml_in = 0
        self.ml_hit = 0
        self.spoof = 0
        self.bert_in = 0
        self.bert_hit = 0


# === LAYER FUNCTIONS ===

def regex_layer_single(row):
    url = str(row.get('URL', '') or "").strip()
    body = str(row.get('POST_Body', '') or "").strip()

    try:
        decoded_url = urllib.parse.unquote_plus(url).lower()
    except Exception:
        decoded_url = url.lower()

    full_payload = decoded_url + " " + body.lower()

    def check(patterns, name):
        for p in patterns:
            if p.search(full_payload):
                return name, f"Matched regex pattern: '{p.pattern[:25]}...'"
        return None

    checks = [
        (CMD_PATTERNS, "Command Injection"),
        (SQLI_PATTERNS, "SQL Injection"),
        (XSS_PATTERNS, "Cross-Site Scripting (XSS)"),
        (LFI_PATTERNS, "Directory Traversal / LFI"),
        (SSRF_PATTERNS, "SSRF"),
        (SHELL_UPLOAD_PATTERNS, "Shell Upload Attempt"),
    ]

    for pats, name in checks:
        res = check(pats, name)
        if res:
            return res[0], res[1]

    if RFI_PATTERN.search(decoded_url):
        return "Remote File Inclusion (RFI)", "Regex found remote protocol"

    if "xml" in full_payload:
        res = check(XXE_PATTERNS, "XXE")
        if res:
            return res[0], res[1]

    return None, None


def ml_layer_single(row):
    url = str(row.get('URL', '') or "").strip()
    try:
        parsed = urllib.parse.urlparse(url)
        query_part = parsed.query
    except Exception:
        query_part = ""

    if not query_part:
        return None, None

    ml_label, ml_conf, ml_evidence = predict_ml_attack(query_part)
    if ml_label != "Benign":
        return ml_label, ml_evidence

    return None, None


def spoof_layer_single(row):
    url = str(row.get('URL', '') or "").strip()

    for p in URL_SPOOF_PATTERNS:
        if p.search(url):
            return "URL Spoofing / Typosquatting", f"Suspicious regex pattern: '{p.pattern}'"

    is_spoof, spoof_ev = predict_url_spoofing(url)
    if is_spoof:
        return "URL Spoofing / Typosquatting", spoof_ev

    try:
        q = urllib.parse.urlparse(url).query
        if q:
            params = urllib.parse.parse_qs(q, keep_blank_values=True)
            for k, v in params.items():
                if len(v) > 1:
                    return "HPP (HTTP Parameter Pollution)", f"Duplicate parameter key: '{k}'"
    except Exception:
        pass

    return None, None


def bert_layer_single(row):
    url = str(row.get('URL', '') or "").strip()
    try:
        parsed = urllib.parse.urlparse(url)
        query_part = parsed.query
    except Exception:
        query_part = ""

    target_text = query_part if query_part else url
    bert_label, confidence, evidence = predict_url_attack(target_text)

    if bert_label != "Benign":
        return bert_label, evidence

    return None, None


# === MAIN PIPELINE ===

def run_full_analysis(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns a DataFrame with columns:
    - attack_type
    - evidence
    - detection_method
    (plus original columns)
    """
    if df.empty:
        df = df.copy()
        df['attack_type'] = []
        df['evidence'] = []
        df['detection_method'] = []
        return df

    df = df.copy().fillna("")
    df['attack_type'] = "Benign"
    df['evidence'] = "No threat detected"
    df['detection_method'] = "None"

    stats = PipelineStats()
    stats.total = len(df)

    print(f"\n🚀 Pipeline started on {stats.total} requests.")

    # --- LAYER 1: REGEX ---
    mask_remaining = df['attack_type'] == "Benign"
    layer1_input = mask_remaining.sum()
    print(f"\n[1] REGEX LAYER")
    print(f"    Input records : {layer1_input}")

    if layer1_input > 0:
        tqdm.pandas(desc="Regex Layer")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: regex_layer_single(row),
            axis=1,
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "Regex"

    mask_remaining = df['attack_type'] == "Benign"
    layer1_passed = mask_remaining.sum()
    layer1_detected = layer1_input - layer1_passed
    stats.regex = layer1_detected

    print(f"    Detected      : {layer1_detected}")
    print(f"    Passed to ML  : {layer1_passed}")

    # --- LAYER 2: ML ---
    layer2_input = layer1_passed
    print(f"\n[2] ML LAYER (Naive Bayes)")
    print(f"    Input records : {layer2_input}")
    stats.ml_in = layer2_input

    if layer2_input > 0:
        tqdm.pandas(desc="ML Layer")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: ml_layer_single(row),
            axis=1,
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "ML"

    mask_remaining = df['attack_type'] == "Benign"
    layer2_passed = mask_remaining.sum()
    layer2_detected = layer2_input - layer2_passed
    stats.ml_hit = layer2_detected

    print(f"    Detected      : {layer2_detected}")
    print(f"    Passed to SPOOF: {layer2_passed}")

    # --- LAYER 3: SPOOF/HPP ---
    layer3_input = layer2_passed
    print(f"\n[3] SPOOFING / HPP LAYER")
    print(f"    Input records : {layer3_input}")

    if layer3_input > 0:
        tqdm.pandas(desc="Spoofing Layer")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: spoof_layer_single(row),
            axis=1,
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "Pattern"

    mask_remaining = df['attack_type'] == "Benign"
    layer3_passed = mask_remaining.sum()
    layer3_detected = layer3_input - layer3_passed
    stats.spoof = layer3_detected

    print(f"    Detected      : {layer3_detected}")
    print(f"    Passed to BERT: {layer3_passed}")

    # --- LAYER 4: BERT ---
    layer4_input = layer3_passed
    print(f"\n[4] AI LAYER (BERT)")
    print(f"    Input records : {layer4_input}")
    stats.bert_in = layer4_input

    if layer4_input > 0:
        tqdm.pandas(desc="BERT Layer")
        subset = df[mask_remaining]
        results = subset.progress_apply(
            lambda row: bert_layer_single(row),
            axis=1,
            result_type='expand'
        )
        detected_mask = results[0].notna()
        detected_idx = results[detected_mask].index

        df.loc[detected_idx, 'attack_type'] = results.loc[detected_idx, 0]
        df.loc[detected_idx, 'evidence'] = results.loc[detected_idx, 1]
        df.loc[detected_idx, 'detection_method'] = "AI"

    mask_remaining = df['attack_type'] == "Benign"
    layer4_passed = mask_remaining.sum()
    layer4_detected = layer4_input - layer4_passed
    stats.bert_hit = layer4_detected

    print(f"    Detected      : {layer4_detected}")
    print(f"    Benign after layers (before bruteforce): {layer4_passed}")

    # --- BRUTEFORCE CHECK (post-processing) ---
    login_mask = df['URL'].astype(str).str.contains("login", case=False, na=False)
    if login_mask.any():
        subset = df[login_mask].copy()
        brute_counts = subset.groupby('Source_IP')['URL'].transform('count')
        candidate_mask = (brute_counts >= 5) & (subset['attack_type'] == 'Benign')
        targets = subset.index[candidate_mask]

        if len(targets) > 0:
            df.loc[targets, 'attack_type'] = "Bruteforce Attack"
            df.loc[targets, 'evidence'] = "High frequency login attempts"
            df.loc[targets, 'detection_method'] = "Pattern"

    # --- FINAL SUMMARY (including Bruteforce) ---
    total = len(df)
    total_threats = (df['attack_type'] != 'Benign').sum()
    regex_det = stats.regex
    ml_det = stats.ml_hit
    spoof_det = stats.spoof
    bert_det = stats.bert_hit
    bruteforce_det = total_threats - (regex_det + ml_det + spoof_det + bert_det)

    print("\n" + "=" * 60)
    print("🛡️  FINAL PIPELINE SUMMARY (INCLUDING BRUTEFORCE)")
    print("=" * 60)
    print(f"Total records            : {total}")
    print(f"Regex detections         : {regex_det}")
    print(f"ML detections            : {ml_det}")
    print(f"Spoof/HPP detections     : {spoof_det}")
    print(f"BERT detections          : {bert_det}")
    print(f"Bruteforce detections    : {bruteforce_det}")
    print(f"Final Benign             : {total - total_threats}")
    print("=" * 60 + "\n")

    return df
