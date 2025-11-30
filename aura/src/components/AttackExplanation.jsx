// src/components/AttackExplanation.jsx
import React from "react";
import { AlertTriangle, Shield, Terminal } from "lucide-react";

const ATTACK_KB = {
  "Command Injection": {
    description:
      "The attacker attempts to execute arbitrary operating system commands on the server.",
    whyExamples: [
      "Payload contains command separators like ';', '|', '&&' or '$(...)' structures.",
      "Presence of system binaries like 'wget', 'curl', 'cat', 'net', or 'whoami'.",
      "Input is likely being passed directly to a shell execution function (e.g., system(), exec())."
    ],
    mitigation: [
      "Avoid system calls; use built-in library functions instead.",
      "If system calls are necessary, use 'exec' with an array of arguments, not a string.",
      "Implement strict allow-listing for allowed characters (e.g., alphanumeric only)."
    ]
  },
  "SQL Injection": {
    description:
      "SQLi happens when untrusted input is concatenated into SQL queries, allowing data theft or modification.",
    whyExamples: [
      "Payload contains SQL keywords like 'UNION SELECT', 'OR 1=1', or 'DROP TABLE'.",
      "Suspicious use of quotes (') and comment markers (--, #) to alter query logic.",
      "Attempts to access system tables like 'information_schema' or 'sysobjects'."
    ],
    mitigation: [
      "Use parameterized queries (Prepared Statements) for ALL database access.",
      "Never construct SQL queries by concatenating strings.",
      "Apply 'Least Privilege' principles to database user accounts."
    ]
  },
  "Cross-Site Scripting (XSS)": {
    description:
      "XSS allows attacker-controlled JavaScript to run in the victim’s browser context.",
    whyExamples: [
      "Payload contains HTML tags like <script>, <iframe>, or events like 'onerror='.",
      "Use of 'javascript:' or 'vbscript:' pseudo-protocols.",
      "Input is intended to be reflected back to other users without encoding."
    ],
    mitigation: [
      "Context-aware output encoding (HTML, JavaScript, CSS, URL) for all user data.",
      "Implement a strong Content Security Policy (CSP).",
      "Use modern frameworks (React, Vue) that auto-escape data by default."
    ]
  },
  "Directory Traversal / LFI": {
    description:
      "Local File Inclusion (LFI) or Path Traversal allows reading arbitrary files on the server.",
    whyExamples: [
      "Use of '../' (dot-dot-slash) sequences to move up directory levels.",
      "Direct references to sensitive system files like '/etc/passwd' or 'C:\\Windows\\win.ini'.",
      "Use of PHP wrappers like 'php://filter' or 'php://input'."
    ],
    mitigation: [
      "Validate user input against a strict allow-list of filenames.",
      "Use functions that strip path information (e.g., basename()) before using file paths.",
      "Run the application with restricted file system permissions (chroot)."
    ]
  },
  "SSRF": {
    description:
      "Server-Side Request Forgery tricks the server into making HTTP requests to internal resources.",
    whyExamples: [
      "Parameter values containing internal IPs (127.0.0.1, 192.168.x.x, 10.x.x.x).",
      "Attempts to access cloud metadata services (e.g., 169.254.169.254).",
      "The server is being asked to fetch a URL provided in the input."
    ],
    mitigation: [
      "Validate target URLs against a strict allow-list of domains.",
      "Block outbound traffic to private IP ranges (RFC 1918) at the firewall level.",
      "Disable unused URL schemas (e.g., gopher://, dict://, file://)."
    ]
  },
  "Remote File Inclusion (RFI)": {
    description:
      "RFI allows an attacker to include a remote file (usually a script) to be executed by the server.",
    whyExamples: [
      "A parameter expecting a filename is given a full URL (http://evil.com/shell.txt).",
      "Attackers trying to force the application to download and run malicious code."
    ],
    mitigation: [
      "Disable 'allow_url_include' in php.ini configuration.",
      "Do not allow user input to dictate files passed to include/require statements.",
      "Verify that inputs match expected local filenames only."
    ]
  },
  "XXE": {
    description:
      "XML External Entity attacks abuse XML parsers to read files or perform SSRF.",
    whyExamples: [
      "Payload contains XML definitions like '<!ENTITY' or '<!DOCTYPE'.",
      "References to 'SYSTEM' identifiers pointing to local files (file:///etc/passwd).",
      "Attempts to make the XML parser connect to external URLs."
    ],
    mitigation: [
      "Disable DTD (Document Type Definition) processing in your XML parser.",
      "Disable external entity expansion (e.g., libxml_disable_entity_loader(true) in PHP).",
      "Use less complex formats like JSON where possible."
    ]
  },
  "Shell Upload Attempt": {
    description:
      "The attacker is trying to upload a web shell script to gain full control of the server.",
    whyExamples: [
      "Filenames ending in executable extensions: .php, .jsp, .asp, .pl, .sh.",
      "Content-Type headers indicating scripts (application/x-php) disguised as images.",
      "Payloads containing known web shell signatures (e.g., c99.php, r57)."
    ],
    mitigation: [
      "Validate file types by checking 'Magic Numbers' (file signature), not just extensions.",
      "Rename uploaded files to random hashes and store them outside the web root.",
      "Enforce 'No Exec' permissions on the upload directory."
    ]
  },
  "URL Spoofing / Typosquatting": {
    description:
      "The request involves domains designed to deceive users (phishing) or abuse logic.",
    whyExamples: [
      "Typos of popular brands (e.g., 'paypa1.com', 'g00gle.com').",
      "Homograph attacks using look-alike characters (Punycode).",
      "Very long, obscure domains or use of '@' to hide the true destination."
    ],
    mitigation: [
      "Monitor for registered domains similar to your brand.",
      "Use visual indicators in UI to highlight external or unverified links.",
      "Strictly validate 'Return-URL' or redirect parameters."
    ]
  },
  "HPP (HTTP Parameter Pollution)": {
    description:
      "The attacker sends multiple parameters with the same name to confuse the application logic.",
    whyExamples: [
      "Query string contains duplicate keys, e.g., '?id=10&id=20'.",
      "Attempts to bypass WAFs that only check the first occurrence of a parameter.",
      "Exploiting inconsistencies in how the server parses duplicate variables."
    ],
    mitigation: [
      "Configure the web server to handle duplicate parameters strictly (e.g., take only the first).",
      "Validate that expected parameters occur only once.",
      "Use URL encoding properly."
    ]
  },
  "Bruteforce Attack": {
    description:
      "Repeated high-volume attempts to guess credentials or resource IDs.",
    whyExamples: [
      "High frequency of requests to login/authentication endpoints from a single IP.",
      "Sequential enumeration of ID parameters (Insecure Direct Object Reference probing).",
      "Volume of traffic exceeds normal human browsing behavior."
    ],
    mitigation: [
      "Implement Rate Limiting and Throttling on sensitive endpoints.",
      "Use CAPTCHAs after a set number of failed attempts.",
      "Monitor and ban IPs exhibiting high error rates (401/403)."
    ]
  },
  "Benign": {
    description: "Normal, safe traffic.",
    whyExamples: ["Standard HTTP requests with no malicious patterns detected."],
    mitigation: ["None required."]
  }
};

const DEFAULT_INFO = {
  description: "This activity has been flagged as suspicious by the analysis engine.",
  whyExamples: [
    "Matches a known attack signature pattern.",
    "Contains anomalous characters or encoding.",
    "See specific tokens for details."
  ],
  mitigation: [
    "Investigate the Source IP.",
    "Review the full request payload.",
    "Block if confirmed malicious."
  ]
};

export default function AttackExplanation({ selectedAttack }) {
  if (!selectedAttack) {
    return null; // nothing clicked yet
  }

  // Fallback to DEFAULT_INFO if the attack type isn't in our KB
  const info = ATTACK_KB[selectedAttack.type] || DEFAULT_INFO;

  const tokens = selectedAttack.tokens || [];

  // Get evidence or fallback
  const evidence = selectedAttack.evidence || "Detailed pattern analysis not available.";

  return (
    <div className="mt-6 border border-white/10 rounded-xl bg-black/60 p-6 space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 text-xl font-semibold text-white">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            {selectedAttack.type}
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Source: {selectedAttack.ip || "unknown"} ▸ Target:{" "}
            {selectedAttack.target || "unknown"}
          </p>
        </div>

        <div className="flex flex-col items-end gap-2">
          <span className="inline-flex items-center px-3 py-1 text-xs rounded-full border border-yellow-500/40 text-yellow-300">
            Severity: {selectedAttack.severity || "N/A"}
          </span>
          <span className="inline-flex items-center px-3 py-1 text-xs rounded-full border border-emerald-500/40 text-emerald-300">
            <Shield className="w-3 h-3 mr-1" />
            Detection: Regex + BERT Attention XAI
          </span>
        </div>
      </div>

      {/* --- NEW SECTION: The Specific "Why" (Evidence Box) --- */}
      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
        <div className="flex items-center gap-2 mb-1">
          <Terminal className="w-4 h-4 text-red-400" />
          <h4 className="text-red-400 text-sm font-bold uppercase tracking-wider">
            Detection Evidence
          </h4>
        </div>
        <p className="text-gray-200 font-mono text-sm break-all pl-6">
          {evidence}
        </p>
      </div>
      {/* ---------------------------------------------------- */}

      {/* What & Why */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-1">
          What this attack means
        </h4>
        <p className="text-sm text-gray-300">{info.description}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <h4 className="text-sm font-semibold text-white mb-1">
            Why this specific request looks suspicious
          </h4>
          <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
            {info.whyExamples.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>

        <div>
          <h4 className="text-sm font-semibold text-white mb-1">
            Mitigation hints for defenders
          </h4>
          <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
            {info.mitigation.map((item, idx) => (
              <li key={idx}>{item}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Advanced tokens section – keep for “XAI proof” */}
      {tokens.length > 0 && (
        <div>
          <h4 className="text-sm font-semibold text-white mb-2">
            Tokens BERT focused on for this request
          </h4>
          <p className="text-xs text-gray-500 mb-3">
            Saliency computed from the [CLS] attention distribution in
            bert-base-uncased.
          </p>
          <div className="flex flex-wrap gap-2">
            {tokens.map((t, idx) => (
              <span
                key={idx}
                className="px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-100 text-xs font-mono"
              >
                {t.token} ({Math.round(t.weight * 100)}%)
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}