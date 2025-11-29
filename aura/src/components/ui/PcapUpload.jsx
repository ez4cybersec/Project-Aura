import { useState } from "react";

export default function PcapUpload() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState(null);
  const [csvFile, setCsvFile] = useState(null);
  const [error, setError] = useState(null);

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a .pcap or .pcapng file first.");
      return;
    }

    setLoading(true);
    setError(null);
    setSummary(null);
    setCsvFile(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("http://127.0.0.1:8000/api/upload-capture/", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      setLoading(false);

      if (!res.ok) {
        setError(data.error || "Something went wrong during analysis.");
        return;
      }

      if (data.summary) {
        setSummary(data.summary);
        setCsvFile(data.csv);
      } else {
        setError(data.message || "No HTTP traffic found in this file.");
      }
    } catch (err) {
      console.error(err);
      setLoading(false);
      setError("Could not connect to backend. Is Django running?");
    }
  };

  return (
    <div className="space-y-6 bg-slate-900/40 border border-slate-700 rounded-xl p-6">
      <div>
        <h2 className="text-xl font-semibold text-white">PCAP Threat Scan</h2>
        <p className="text-sm text-slate-400">
          Upload a .pcap or .pcapng file to analyze for SQLi, XSS, LFI, SSRF, bruteforce, URL spoofing, and shell uploads.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <input
          type="file"
          accept=".pcap,.pcapng"
          onChange={(e) => setFile(e.target.files[0] || null)}
          className="text-sm text-slate-200"
        />
        <button
          onClick={handleUpload}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-600 text-white text-sm font-medium"
        >
          {loading ? "Analyzing..." : "Upload & Analyze"}
        </button>
      </div>

      {error && (
        <div className="text-sm text-red-400">
          {error}
        </div>
      )}

      {summary && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-white">Attack Summary</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {Object.entries(summary).map(([attack, count]) => (
              <div
                key={attack}
                className="flex justify-between items-center px-3 py-2 rounded-lg bg-slate-800 text-sm text-slate-100"
              >
                <span>{attack}</span>
                <span className="font-semibold">{count}</span>
              </div>
            ))}
          </div>

          {csvFile && (
            <a
              href={`http://127.0.0.1:8000/uploads/${csvFile}`}
              className="inline-block mt-3 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium"
              download
            >
              Download Full CSV Report
            </a>
          )}
        </div>
      )}
    </div>
  );
}
