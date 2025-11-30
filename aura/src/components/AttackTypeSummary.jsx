/* eslint-disable react/prop-types */
import React, { useMemo } from "react";
import { ShieldAlert, ShieldCheck, Info } from "lucide-react";

const ATTACK_KNOWLEDGE = {
  "SQL Injection": {
    description:
      "Attacker injects malicious SQL into input fields to read or modify database data.",
    mitigations: [
      "Use parameterized queries / prepared statements.",
      "Never concatenate user input directly into SQL.",
      "Least-privilege DB accounts (no DROP/ALTER for app user).",
      "Input validation and allow-lists for critical fields."
    ]
  },
  "Cross-Site Scripting (XSS)": {
    description:
      "Attacker injects malicious JavaScript into pages viewed by other users.",
    mitigations: [
      "HTML-encode output (especially <, >, \", ').",
      "Use Content Security Policy (CSP) to block inline scripts.",
      "Sanitize user input on server side.",
      "Disable unsafe DOM APIs where possible (innerHTML, document.write)."
    ]
  },
  "Directory Traversal / LFI": {
    description:
      "User-controlled paths are used to read files from the server (../etc/passwd etc.).",
    mitigations: [
      "Use fixed base directories and resolve/normalize paths.",
      "Block '..', '%2e%2e', and absolute paths in user input.",
      "Use allow-lists of allowed filenames or IDs.",
      "Run services with minimal filesystem permissions."
    ]
  },
  "Remote File Inclusion (RFI)": {
    description:
      "Application loads remote code or content from attacker-controlled URLs.",
    mitigations: [
      "Disable remote includes in language/framework configuration.",
      "Never include files based on raw user input.",
      "Use strict allow-lists for any dynamic include/load features.",
      "Filter out http(s)://, ftp:// and other URL schemes in file paths."
    ]
  },
  SSRF: {
    description:
      "Server is tricked into making HTTP requests to internal services (127.0.0.1, cloud metadata).",
    mitigations: [
      "Block requests to private IP ranges and localhost.",
      "Use URL allow-list (only known external APIs).",
      "Enforce network egress rules / firewall.",
      "Avoid fetching arbitrary URLs from user input."
    ]
  },
  "URL Spoofing / Typosquatting": {
    description:
      "User is redirected to a deceptive domain that visually imitates a trusted site.",
    mitigations: [
      "Show full, verified destination URLs to users.",
      "Use HSTS and pinned certificates for your domains.",
      "Educate users to spot look-alike domains.",
      "Monitor for typosquat domains using threat intel services."
    ]
  },
  "Shell Upload Attempt": {
    description:
      "Attacker uploads a script (php, jsp, aspx, sh, etc.) to execute commands on the server.",
    mitigations: [
      "Restrict allowed file types and validate MIME types.",
      "Store uploads outside the web root or on object storage.",
      "Strip execute permissions from upload directories.",
      "Scan uploads with AV / WAF rules for web shells."
    ]
  },
  "Bruteforce Attack": {
    description:
      "Repeated login attempts from the same source to guess passwords.",
    mitigations: [
      "Implement account lockout or throttling after N failures.",
      "Use strong password policies and MFA.",
      "Monitor and block suspicious IPs via rate limiting / WAF.",
      "Use CAPTCHA or device fingerprinting for abuse control."
    ]
  },
  "Command Injection": {
    description:
      "User input is concatenated into OS commands (shell, powershell, etc.).",
    mitigations: [
      "Avoid shell calls; use safe language APIs instead.",
      "If shell is required, use parameter arrays, not string concat.",
      "Escape and strictly validate all parameters.",
      "Run services with least privileges and AppArmor/SELinux profiles."
    ]
  },
  "HPP (HTTP Parameter Pollution)": {
    description:
      "Attacker sends duplicated HTTP parameters to confuse backend logic or WAF rules.",
    mitigations: [
      "Normalize request parameters on the server (first or last wins).",
      "Avoid different components interpreting parameters differently.",
      "Log and alert on repeated suspicious parameters.",
      "Use modern frameworks that handle duplicate params safely."
    ]
  },
  XXE: {
    description:
      "XML parser processes external entities to read local files or perform SSRF.",
    mitigations: [
      "Disable DTDs / external entities in XML parsers.",
      "Use safe, modern data formats (JSON) when possible.",
      "Apply least-privilege filesystem and network permissions.",
      "Validate and sanitize any uploaded XML documents."
    ]
  }
};

export default function AttackTypeSummary({ attacks = [] }) {
  const summary = useMemo(() => {
    const counts = {};
    attacks.forEach((a) => {
      const type = a.type || a.attack_type;
      if (!type || type === "Benign") return;
      counts[type] = (counts[type] || 0) + 1;
    });
    return counts;
  }, [attacks]);

  const attackTypes = Object.keys(summary);

  if (attackTypes.length === 0) {
    return null; // nothing to show
  }

  return (
    <div className="mt-6 p-6 border border-white/10 rounded-xl bg-black/40 backdrop-blur-sm space-y-4">
      <div className="flex items-center gap-2 mb-2">
        <ShieldAlert className="w-5 h-5 text-purple-400" />
        <h3 className="text-lg font-semibold text-white">
          Detected Attack Types & Mitigation Guide
        </h3>
      </div>
      <p className="text-sm text-gray-400 mb-4">
        This capture contains the following attack categories. For each type you
        can see a short explanation and practical hardening steps.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {attackTypes.map((type) => {
          const info = ATTACK_KNOWLEDGE[type] || {
            description: "No detailed description available for this type yet.",
            mitigations: ["Review server-side validation and access controls."]
          };

          return (
            <div
              key={type}
              className="border border-white/10 rounded-lg bg-black/60 p-4 flex flex-col gap-2"
            >
              <div className="flex items-center justify-between gap-2">
                <div>
                  <h4 className="text-sm font-semibold text-white">
                    {type}
                  </h4>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Events in this capture:{" "}
                    <span className="font-mono text-blue-300">
                      {summary[type]}
                    </span>
                  </p>
                </div>
                <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-300">
                  <ShieldCheck className="w-3 h-3" />
                  Mitigation
                </span>
              </div>

              <p className="text-xs text-gray-300 leading-snug">
                {info.description}
              </p>

              <div className="mt-1 space-y-1">
                {info.mitigations.map((m, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-gray-300">
                    <span className="mt-[5px] w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span>{m}</span>
                  </div>
                ))}
              </div>

              <div className="mt-2 flex items-center gap-1 text-[11px] text-gray-500">
                <Info className="w-3 h-3" />
                These are general best practices. Apply them on your web
                server, WAF, and application code.
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
