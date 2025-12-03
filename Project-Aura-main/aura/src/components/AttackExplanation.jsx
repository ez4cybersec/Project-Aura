import React, { useState, useEffect } from "react";
import { ShieldAlert, Info, Calendar, Globe } from "lucide-react";
import { apiClient } from "../lib/apiClient";
import AttackVisualizer from "./AttackVisualizer"; 

// --- MITIGATION KNOWLEDGE BASE ---
const MITIGATION_ADVICE = {
  "SQL Injection": "Use parameterized queries (Prepared Statements). Never concatenate user input directly into SQL strings.",
  "Cross-Site Scripting (XSS)": "Escape all user-generated content before displaying it. Implement a Content Security Policy (CSP).",
  "Command Injection": "Avoid system shell calls. Use language-specific libraries instead (e.g., use Python's `os` module, not `os.system`).",
  "Bruteforce Attack": "Implement rate limiting, account lockout policies after N failed attempts, and use Multi-Factor Authentication (MFA).",
  "Directory Traversal / LFI": "Validate user input against a whitelist of allowed files. Disable `allow_url_include` in server configs.",
  "Remote File Inclusion (RFI)": "Disable remote file inclusion in your server configuration (e.g., `allow_url_include=0` in php.ini).",
  "Benign": "This request appears safe. No action required."
};

export default function AttackExplanation({ selectedAttack }) {
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (selectedAttack) {
      setLoading(true);
      setExplanation(null); 

      apiClient.getAttackExplanation(selectedAttack.url).then((data) => {
        // Handle cases where the API might return null or error
        setExplanation(data ? data.explanation : []);
        setLoading(false);
      });
    }
  }, [selectedAttack]);

  // Format Timestamp Helper
  const formatTime = (ts) => {
    if (!ts) return "N/A";
    try {
      // Handle Unix timestamp (seconds or milliseconds)
      const date = new Date(parseFloat(ts) * 1000); 
      return date.toLocaleString();
    } catch (e) {
      return ts;
    }
  };

  if (!selectedAttack) {
    return (
      <div className="p-8 border border-white/10 rounded-xl bg-black/20 text-center text-gray-500 flex flex-col items-center justify-center min-h-[200px]">
        <Info size={32} className="mb-3 opacity-50" />
        <p>Select an event from the table to view deep AI analysis.</p>
      </div>
    );
  }

  const advice = MITIGATION_ADVICE[selectedAttack.type] || "Investigate source IP and block if suspicious.";

  return (
    <div className="p-6 border border-white/10 rounded-xl bg-black/40 backdrop-blur-md shadow-xl">
      
      {/* Header Section */}
      <div className="flex justify-between items-start mb-6 border-b border-white/10 pb-4">
        <div>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
             {selectedAttack.type}
          </h3>
          <p className="text-red-400 text-sm font-mono mt-1 uppercase tracking-wider">
            {selectedAttack.severity} SEVERITY
          </p>
        </div>
        <div className="text-right text-xs text-gray-500 space-y-1">
           <div className="flex items-center justify-end gap-2">
             <Calendar size={14} /> {formatTime(selectedAttack.timestamp)}
           </div>
           <div className="flex items-center justify-end gap-2">
             <Globe size={14} /> {selectedAttack.ip}
           </div>
        </div>
      </div>

      {/* AI Visualizer */}
      {loading ? (
        <div className="p-8 text-center animate-pulse text-blue-400 bg-black/20 rounded-lg">
          🧠 AI is analyzing the payload...
        </div>
      ) : (
        <AttackVisualizer explanationData={explanation} />
      )}

      {/* Mitigation Section */}
      <div className="mt-6 bg-blue-900/20 border-l-4 border-blue-500 p-4 rounded-r-lg">
        <div className="flex items-start gap-3">
          <ShieldAlert className="text-blue-400 shrink-0" size={24} />
          <div>
            <h4 className="font-bold text-blue-100 text-sm uppercase mb-1">Recommended Mitigation</h4>
            <p className="text-gray-300 text-sm leading-relaxed">
              {advice}
            </p>
          </div>
        </div>
      </div>

    </div>
  );
}