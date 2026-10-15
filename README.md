```powershell
cd auraa-frontend
npm ci
npm run dev -- --port 5173 --strictPort
```

Open [http://localhost:5173](http://localhost:5173). Frontend requests currently target `http://127.0.0.1:8000`; Django allows the localhost and loopback origins on port `5173`. Using different addresses or ports requires updating the frontend request URLs and backend CORS settings.

## Usage

1. Open **Scan** at `/scan` and select a supported capture or CSV file.
2. Submit the upload to start background analysis.
3. Open `/dashboard` to inspect results as the pipeline writes them.
4. Select an attack to request an explanation and mitigation advice.
5. Use `/docs` and `/heuristics` to explore the application's documentation views.

### CSV input format

The upload endpoint reads CSV columns directly, without applying the alias normalization helper in `parsers.py`. Use these exact column names:

| Column | Content |
| --- | --- |
| `Timestamp` | Unix timestamp in seconds |
| `Source_IP` | Source IPv4 or IPv6 address |
| `Dest_IP` | Destination address |
| `Method` | HTTP method, such as `GET` or `POST` |
| `URL` | Request URL including query parameters |
| `POST_Body` | Request body, or an empty string |
| `Status_Code` | Numeric HTTP response status; `0` if unavailable |

Example:

```csv
Timestamp,Source_IP,Dest_IP,Method,URL,POST_Body,Status_Code
1735689600,192.0.2.10,198.51.100.20,GET,http://example.test/search?q=hello,,200
```

## API Reference

All paths below are relative to `http://127.0.0.1:8000`.

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/upload-capture/` | Accept multipart form data with a `file` field; return a processing status and result filename |
| `GET` | `/api/attacks/` | Return non-benign findings from the latest analysis |
| `GET` | `/api/stats/` | Return total records, threats, heuristic breaches, health, and detection-method breakdown |
| `GET` | `/api/traffic/` | Return request counts grouped into one-second intervals |
| `POST` | `/api/explain/` | Accept JSON with `attack_data` and `attack_type`; return explanation and mitigation |
| `POST` | `/api/scan/pcap/` | Legacy acknowledgement endpoint; does not perform analysis |

Upload example in PowerShell:

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/upload-capture/ -F "file=@C:\captures\sample.pcap"
```

## Development Checks

From `auraa-frontend`:

```powershell
npm run lint
npm run build
```

From `server/backend`, with the virtual environment active:

```powershell
python manage.py check
python manage.py test
```

The backend test module is currently a scaffold with no implemented test cases. These commands do not establish detection accuracy or end-to-end model behavior.

## Operational Notes and Limitations

- **HTTP visibility:** Capture parsing uses TShark's `http` display filter. Encrypted HTTPS payloads are not automatically decrypted.
- **Heuristic outcomes:** Labels such as "Successful", "Blocked", and "breaches" are inferred from response codes and payload rules. They do not confirm exploitation or compromise. The health metric is derived from the proportion of flagged requests.
- **Shared latest results:** Dashboard data is not isolated by user or upload ID. Concurrent uploads can change which analysis is displayed.
- **Background processing:** Jobs use daemon threads rather than a durable task queue. A server restart can interrupt analysis, and processing failures are logged to the backend console.
- **File retention:** Input uploads are deleted after processing; generated analysis CSV files remain in `uploads/` until removed.
- **Development configuration:** The backend enables debug mode and the analysis endpoints do not implement user authentication. Production deployment requires appropriate security configuration and access controls.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Capture produces no requests | Verify `tshark --version` works and the capture contains HTTP traffic visible to TShark |
| Dashboard cannot reach the API | Start Django on port `8000` and use frontend port `5173` with an allowed origin |
| ML detections are absent | Verify that both matching `.joblib` artifacts exist in `ml_model/` |
| Model loading or explanation fails | Check backend logs, model files, available memory, network access, and Hugging Face permissions |
| Results appear unchanged | Wait for the five-second refresh and inspect backend logs for background-task errors |
| A `.cap` upload is rejected | Use a supported `.pcap`, `.pcapng`, or `.csv` file; the backend rejects `.cap` despite the frontend picker accepting it |

