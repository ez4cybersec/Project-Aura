import subprocess
import json
import pandas as pd


def pcap_to_dataframe(file_path: str) -> pd.DataFrame:
    command = [
        "tshark",
        "-r", file_path,
        "-Y", "http",          # include both requests + responses
        "-T", "json",
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0 or not result.stdout.strip():
        return pd.DataFrame(columns=["Timestamp", "URL", "POST_Body", "Source_IP", "Status_Code"])

    packets = json.loads(result.stdout)
    rows = []

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        http = layers.get("http", {})
        ip = layers.get("ip", {})
        frame = layers.get("frame", {})

        def get_field(layer: dict, key: str) -> str:
            val = layer.get(key)
            if isinstance(val, list) and val:
                return val[0]
            if isinstance(val, str):
                return val
            return ""

        timestamp = get_field(frame, "frame.time")

        full_uri = get_field(http, "http.request.full_uri")
        host = get_field(http, "http.host")
        uri = get_field(http, "http.request.uri")

        if full_uri:
            url = full_uri
        elif host or uri:
            url = f"http://{host}{uri}"
        else:
            url = ""

        src_ip = get_field(ip, "ip.src")
        body = get_field(http, "http.file_data")

        # <-- NEW: try to read response status code if present
        status_code = get_field(http, "http.response.code") or get_field(
            http, "http.response.code"
        )

        # Only log rows that have a URL (requests); status may be blank
        if url:
            rows.append({
                "Timestamp": timestamp,
                "URL": url,
                "POST_Body": body,
                "Source_IP": src_ip,
                "Status_Code": status_code,
            })

    return pd.DataFrame(rows)

