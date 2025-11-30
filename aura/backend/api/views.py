from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

import os
import uuid
import urllib.parse

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

import pandas as pd

from .parsers import pcap_to_dataframe
from .threat_analyzer import run_full_analysis


# ============================================================
#  Upload endpoints
# ============================================================

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def upload_pcap(request):
    """
    Simple test endpoint (not used by frontend now).
    """
    return Response({"status": "ok", "message": "PCAP received successfully"})


@csrf_exempt
def upload_capture(request):
    """
    POST /api/upload-capture/
    Main endpoint used by frontend to upload a PCAP/PCAPNG,
    run analysis, and save analysis_*.csv in /uploads.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    if "file" not in request.FILES:
        return JsonResponse({"error": "Missing file parameter"}, status=400)

    up_file = request.FILES["file"]
    _, ext = os.path.splitext(up_file.name)
    ext = ext.lower()

    if ext not in [".pcap", ".pcapng"]:
        return JsonResponse({"error": "Only .pcap or .pcapng supported"}, status=400)

    upload_dir = os.path.join(settings.BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    tmp_name = f"{uuid.uuid4()}{ext}"
    tmp_path = os.path.join(upload_dir, tmp_name)

    # save uploaded file to disk
    with open(tmp_path, "wb+") as dest:
        for chunk in up_file.chunks():
            dest.write(chunk)

    try:
        df = pcap_to_dataframe(tmp_path)
        if df.empty:
            return JsonResponse({"message": "No HTTP traffic found"}, status=200)

        analyzed = run_full_analysis(df)

        result_name = f"analysis_{uuid.uuid4()}.csv"
        result_path = os.path.join(upload_dir, result_name)
        analyzed.to_csv(result_path, index=False)

        return JsonResponse({
            "message": "Analysis complete",
            "summary": analyzed["attack_type"].value_counts().to_dict(),
            "csv": result_name,
            "total_requests": len(analyzed),
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# ============================================================
#  Helpers for reading latest analysis CSV
# ============================================================

UPLOAD_DIR = os.path.join(settings.BASE_DIR, "uploads")


def _get_latest_csv_path():
    """Return path to the most recent analysis_*.csv file, or None."""
    if not os.path.exists(UPLOAD_DIR):
        return None

    csv_files = [
        f for f in os.listdir(UPLOAD_DIR)
        if f.endswith(".csv") and f.startswith("analysis_")
    ]
    if not csv_files:
        return None

    csv_files.sort(
        key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR, f)),
        reverse=True,
    )
    return os.path.join(UPLOAD_DIR, csv_files[0])


def _severity_for_attack(attack_type: str) -> str:
    high = {
        "Command Injection",
        "SSRF",
        "Directory Traversal / LFI",
        "Remote File Inclusion (RFI)",
        "Shell Upload Attempt",
        "Bruteforce Attack",
    }
    medium = {
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "URL Spoofing / Typosquatting",
        "XXE",
        "HPP (HTTP Parameter Pollution)",
    }

    if attack_type in high:
        return "HIGH"
    if attack_type in medium:
        return "MEDIUM"
    if attack_type == "Benign":
        return "INFO"
    return "LOW"


def _filtered_attack_rows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply the same filtering logic used by /api/attacks/:
    - drop Benign
    - drop any 'sleep' URLs (noise)
    """
    df = df.copy()
    df["URL_str"] = df["URL"].astype(str).str.lower()
    mask = (df["attack_type"] != "Benign") & ~df["URL_str"].str.contains("sleep")
    return df[mask]


# ============================================================
#  /api/attacks/  – detailed rows for table + donut
# ============================================================

# In views.py

def attacks(request):
    """
    GET /api/attacks/
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse([], safe=False)

    df = pd.read_csv(csv_path).fillna("")

    # apply the central filtering logic
    df_attacks = _filtered_attack_rows(df)

    records = []
    for idx, row in df_attacks.iterrows():
        attack_type = row.get("attack_type", "Benign")
        src_ip = row.get("Source_IP", "")
        url = row.get("URL", "")
        timestamp = row.get("Timestamp", "")
        
        # 1. Get Status Code (now extracted by parsers.py)
        # Handle cases where it might be empty string or float
        raw_status = row.get("Status_Code", 0)
        try:
            status_code = int(float(str(raw_status))) if raw_status != "" else 0
        except:
            status_code = 0

        evidence = row.get("evidence", "Pattern match detected")

        try:
            parsed = urllib.parse.urlparse(str(url))
            target = parsed.netloc or url
        except Exception:
            target = url

        severity = _severity_for_attack(attack_type)

        # 2. Determine Result: Successful vs Unsuccessful
        # 2xx = Success (The server executed the request)
        # 4xx/5xx = Blocked/Failed (The server rejected it)
        if 200 <= status_code < 300:
            result_label = "Successful" 
            # Note: "Successful" for an ATTACK is bad for the server, 
            # but accurate for the log.
        elif status_code == 0:
            result_label = "Unknown" # No response captured
        else:
            result_label = "Blocked" # 403, 404, 500 etc.

        records.append({
            "id": int(idx) + 1,
            "timestamp": timestamp,
            "ip": src_ip,
            "target": target,
            "type": attack_type,
            "severity": severity,
            "status_code": status_code if status_code > 0 else "N/A",
            "status": "Threat",
            "result": result_label, # <--- Now dynamic!
            "url": url,
            "evidence": evidence,
        })

    return JsonResponse(records, safe=False)


# ============================================================
#  /api/stats/  – cards at top of dashboard
# ============================================================

def stats(request):
    """
    GET /api/stats/
    Return high-level stats for StatCards.

    - total    = all HTTP events (rows in CSV)
    - threats  = number of rows after filtering (same as /api/attacks/)
    - breaches = subset of threats considered "high impact"
    - health   = 100 - (threats / total * 100)
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse({
            "total": 0,
            "threats": 0,
            "breaches": 0,
            "health": 100,
        })

    df = pd.read_csv(csv_path).fillna("")

    total = len(df)

    # same filtering as attacks()
    df_attacks = _filtered_attack_rows(df)
    threats = len(df_attacks)

    breach_types = {
        "Command Injection",
        "SSRF",
        "Directory Traversal / LFI",
        "Remote File Inclusion (RFI)",
        "Shell Upload Attempt",
        "Bruteforce Attack",
    }
    breaches = int(df_attacks["attack_type"].isin(breach_types).sum())

    if total == 0:
        health = 100
    else:
        risk = min(100, int((threats / total) * 100))
        health = max(0, 100 - risk)

    return JsonResponse({
        "total": int(total),
        "threats": int(threats),
        "breaches": int(breaches),
        "health": int(health),
    })


# ============================================================
#  /api/traffic/  – aggregated data for AttackMap
# ============================================================

def traffic(request):
    """
    GET /api/traffic/
    Return time-series data for the AttackMap (AreaChart).
    Groups attacks by time intervals (e.g., Seconds/Minutes) to show traffic spikes.
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse([], safe=False)

    df = pd.read_csv(csv_path).fillna("")
    
    # Filter out noise
    df_attacks = _filtered_attack_rows(df)

    if df_attacks.empty:
        return JsonResponse([], safe=False)

    # --- TIME SERIES LOGIC ---
    try:
        # Convert Timestamp column to datetime objects
        # We assume timestamp is Unix float (from Scapy) or standard string
        # 'coerce' handles errors gracefully
        df_attacks['dt'] = pd.to_datetime(df_attacks['Timestamp'], unit='s', errors='coerce')
        
        # Drop rows where timestamp couldn't be parsed
        df_attacks = df_attacks.dropna(subset=['dt'])

        if df_attacks.empty:
            return JsonResponse([], safe=False)

        # Resample/Group by 1-second or 1-minute intervals
        # 'S' = Second, 'T' = Minute. 
        # Using 'S' gives a granular graph for short PCAP captures.
        timeline = (
            df_attacks.set_index('dt')
            .resample('s')['attack_type']
            .count()
            .reset_index(name='attacks')
        )

        # Format for Frontend
        data = []
        for _, row in timeline.iterrows():
            data.append({
                # Format time as HH:MM:SS for the X-Axis
                "time": row['dt'].strftime('%H:%M:%S'),
                "attacks": int(row['attacks'])
            })
            
        return JsonResponse(data, safe=False)

    except Exception as e:
        print(f"Error generating traffic chart: {e}")
        return JsonResponse([], safe=False)





try:
    from .bert_predictor import get_explanation # Import the new explainer
except ImportError:
    from bert_predictor import get_explanation


def explain_attack(request, attack_id: int):
    """
    GET /api/explain/<attack_id>/
    Uses the new get_explanation function from bert_predictor
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse({"error": "No analysis file found"}, status=400)

    try:
        df = pd.read_csv(csv_path).fillna("")
    except Exception:
        return JsonResponse({"error": "Failed to read analysis file"}, status=500)

    idx = int(attack_id) - 1
    if idx < 0 or idx >= len(df):
        return JsonResponse({"error": "Invalid attack id"}, status=404)

    row = df.iloc[idx]
    
    # Combine URL and Body for context
    text = f"{row.get('URL', '')} {row.get('POST_Body', '')}".strip()
    attack_type = row.get("attack_type", "Unknown")
    evidence = row.get("evidence", "")

    # Call the new logic
    features = get_explanation(text)

    return JsonResponse({
        "attack_id": attack_id,
        "attack_type": attack_type,
        "evidence": evidence,
        "features": features,
    })
