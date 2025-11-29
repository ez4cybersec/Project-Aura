from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

@api_view(['POST'])
@parser_classes([MultiPartParser, FormParser])
def upload_pcap(request):
    # In a real app, we would process request.FILES['file'] here
    return Response({"status": "ok", "message": "PCAP received successfully"})




import os
import uuid
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import os, uuid
import pandas as pd

from .parsers import pcap_to_dataframe
from .threat_analyzer import run_full_analysis


@csrf_exempt
def upload_capture(request):
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
            "total_requests": len(analyzed)
        })
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


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


# def attacks(request):
#     """
#     GET /api/attacks/
#     Return list of analyzed requests for ThreatLogTable & ThreatDonut.
#     """
#     csv_path = _get_latest_csv_path()
#     if not csv_path:
#         return JsonResponse([], safe=False)

#     df = pd.read_csv(csv_path).fillna("")

#     records = []
#     for idx, row in df.iterrows():
#         attack_type = row.get("attack_type", "Benign")
#         src_ip = row.get("Source_IP", "")
#         url = row.get("URL", "")

#         records.append({
#             "id": int(idx) + 1,
#             "type": attack_type,                            # used by ThreatDonut & filter
#             "ip": src_ip,                                   # used in filter
#             "status": "Threat" if attack_type != "Benign" else "Benign",
#             "url": url,
#         })

#     return JsonResponse(records, safe=False)


def stats(request):
    """
    GET /api/stats/
    Return high-level stats for StatCards.
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
    threats = int((df["attack_type"] != "Benign").sum())

    # Consider these as "breaches" (you can tune this list)
    breach_types = [
        "Command Injection",
        "SSRF",
        "Directory Traversal / LFI",
        "Remote File Inclusion (RFI)",
        "Shell Upload Attempt",
        "Bruteforce Attack",
    ]
    breaches = int(df["attack_type"].isin(breach_types).sum())

    # Simple health metric: more threats → lower health
    if total == 0:
        health = 100
    else:
        risk = min(100, int((threats / total) * 100))
        health = max(0, 100 - risk)

    return JsonResponse({
        "total": total,
        "threats": threats,
        "breaches": breaches,
        "health": health,
    })


def traffic(request):
    """
    GET /api/traffic/
    Return aggregated traffic per source IP for AttackMap.
    (simple version – just count requests by IP)
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse([], safe=False)

    df = pd.read_csv(csv_path).fillna("")

    if "Source_IP" not in df.columns:
        return JsonResponse([], safe=False)

    grouped = (
        df.groupby("Source_IP")["attack_type"]
        .count()
        .reset_index(name="count")
    )

    data = []
    for _, row in grouped.iterrows():
        data.append({
            "ip": row["Source_IP"],
            "count": int(row["count"]),
        })

    return JsonResponse(data, safe=False)


import urllib.parse

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


def attacks(request):
    """
    GET /api/attacks/
    Return list of analyzed *attacks* (no benign / sleep noise)
    for ThreatLogTable & ThreatDonut.
    """
    csv_path = _get_latest_csv_path()
    if not csv_path:
        return JsonResponse([], safe=False)

    df = pd.read_csv(csv_path).fillna("")

    records = []
    for idx, row in df.iterrows():
        attack_type = row.get("attack_type", "Benign")
        src_ip = row.get("Source_IP", "")
        url = row.get("URL", "")
        timestamp = row.get("Timestamp", "")
        status_code = row.get("Status_Code", "")


        # 1) Hide normal traffic completely
        if attack_type == "Benign":
            continue

        # 2) Also hide any "sleep" URL you used for noise/testing
        if "sleep" in str(url).lower():
            continue

        # derive a simple "target" from URL (host)
        try:
            parsed = urllib.parse.urlparse(str(url))
            target = parsed.netloc or url
        except Exception:
            target = url

        severity = _severity_for_attack(attack_type)

        records.append({
            "id": int(idx) + 1,
            "timestamp": timestamp,
            "ip": src_ip,
            "target": target,
            "type": attack_type,
            "severity": severity,
            "status_code": status_code,  # you can map real status later if you parse responses
            "status": "Threat",           # used in Dashboard filter
            "result": "Blocked",          # or "Allowed" if you ever add that logic
            "url": url,
        })

    return JsonResponse(records, safe=False)
