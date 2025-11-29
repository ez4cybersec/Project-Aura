import React, { useState } from "react";
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileJson,
  FileSpreadsheet,
  Download,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Flag,
} from "lucide-react";

export default function ThreatLogTable({ attacks = [], onSearch }) {
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  // Use passed attacks directly as they are filtered by parent
  const filteredData = attacks;

  // Pagination Logic
  const totalPages = Math.max(1, Math.ceil(filteredData.length / itemsPerPage));
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedData = filteredData.slice(
    startIndex,
    startIndex + itemsPerPage
  );

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
    }
  };

  // Badge Logic: Returns styles based on severity
  const getSeverityBadge = (severity) => {
    const level = (severity || "LOW").toString().toUpperCase();

    switch (level) {
      case "CRITICAL":
      case "CRIT":
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-red-500/10 text-red-500 border border-red-500/20">
            CRITICAL
          </span>
        );
      case "HIGH":
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-orange-500/10 text-orange-500 border border-orange-500/20">
            HIGH
          </span>
        );
      case "MEDIUM":
      case "MED":
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-yellow-500/10 text-yellow-500 border border-yellow-500/20">
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-blue-500/10 text-blue-500 border border-blue-500/20">
            LOW
          </span>
        );
    }
  };

  // Verdict Logic – use status/result/status_code from backend
  const getVerdictBadge = (status, verdict, statusCode) => {
    // "Breach confirmed" path – you can tune this later
    if (
      verdict === "BREACH CONFIRMED" ||
      status === "Success" ||
      statusCode === 200
    ) {
      return (
        <span className="flex items-center gap-1.5 text-red-500 font-bold text-xs tracking-wide px-2 py-1 bg-red-500/10 rounded border border-red-500/20">
          <AlertTriangle className="w-3 h-3" /> BREACH CONFIRMED
        </span>
      );
    } else if (status === "Flagged") {
      return (
        <span className="flex items-center gap-1.5 text-yellow-500 font-medium text-xs tracking-wide px-2 py-1 bg-yellow-500/10 rounded border border-yellow-500/20">
          <Flag className="w-3 h-3" /> FLAGGED
        </span>
      );
    }

    // Default → blocked
    return (
      <span className="flex items-center gap-1.5 text-emerald-500 font-medium text-xs tracking-wide px-2 py-1 bg-emerald-500/10 rounded border border-emerald-500/20">
        <ShieldCheck className="w-3 h-3" /> {verdict || "BLOCKED"}
      </span>
    );
  };

  const exportCSV = () => {
    const headers = [
      "Timestamp",
      "Source IP",
      "Target",
      "Attack Vector",
      "Severity",
      "Verdict",
      "Status Code",
      "Response Size",
    ];

    const csvContent = [
      headers.join(","),
      ...filteredData.map((row) => {
        const verdict =
          row.result ||
          (row.status === "Success" || row.status_code === 200
            ? "BREACH CONFIRMED"
            : "BLOCKED");

        return [
          row.timestamp || "",
          row.ip || "",
          `"${(row.target || "").replace(/"/g, '""')}"`,
          row.type || "",
          row.severity || "LOW",
          verdict,
          row.status_code || "",
          row.response_size || "",
        ].join(",");
      }),
    ].join("\n");

    const blob = new Blob([csvContent], {
      type: "text/csv;charset=utf-8;",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aura_threat_logs_${new Date().toISOString()}.csv`;
    link.click();
  };

  const exportJSON = () => {
    const jsonContent = JSON.stringify(filteredData, null, 2);
    const blob = new Blob([jsonContent], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aura_threat_logs_${new Date().toISOString()}.json`;
    link.click();
  };

  return (
    <div className="w-full space-y-4 p-6 border border-white/10 rounded-xl bg-black/40 backdrop-blur-md shadow-sm">
      {/* Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2">
        <div>
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-blue-500" />
            Live Threat Stream
          </h3>
          <p className="text-sm text-gray-500">
            Real-time analysis of incoming HTTP requests.
          </p>
        </div>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
          {/* Search Input */}
          <div className="relative w-full md:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search IP, Type, Status..."
              className="w-full pl-10 pr-4 py-2 bg-black/50 border border-white/10 rounded-lg text-sm text-white placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all"
              onChange={(e) => {
                if (onSearch) onSearch(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>

          {/* Export Dropdown */}
          <div className="relative">
            <button
              onClick={() => setIsExportOpen(!isExportOpen)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 text-sm font-medium rounded-lg border border-blue-500/20 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export Data
              <ChevronDown
                className={`w-4 h-4 transition-transform ${
                  isExportOpen ? "rotate-180" : ""
                }`}
              />
            </button>

            {isExportOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-black/90 border border-white/10 rounded-lg shadow-xl backdrop-blur-xl z-50 py-1">
                <button
                  onClick={() => {
                    exportCSV();
                    setIsExportOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors text-left"
                >
                  <FileSpreadsheet className="w-4 h-4 text-green-400" />
                  Export as CSV
                </button>
                <button
                  onClick={() => {
                    exportJSON();
                    setIsExportOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors text-left"
                >
                  <FileJson className="w-4 h-4 text-yellow-400" />
                  Export as JSON
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-white/5">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-gray-400 uppercase bg-white/5">
            {/* Stage Headers */}
            <tr className="border-b border-white/10">
              <th
                colSpan="3"
                className="px-6 py-2 text-left font-bold text-blue-400 text-sm"
              >
                1. DATA COLLECTION
                <span className="ml-2 text-xs font-normal text-gray-500">
                  Real-time Traffic Stream
                </span>
              </th>
              <th
                colSpan="3"
                className="px-6 py-2 text-left font-bold text-yellow-400 text-sm"
              >
                2. ANALYSIS
                <span className="ml-2 text-xs font-normal text-gray-500">
                  Pattern Recognition
                </span>
              </th>
              <th
                colSpan="1"
                className="px-6 py-2 text-left font-bold text-red-400 text-sm"
              >
                3. RESULT
                <span className="ml-2 text-xs font-normal text-gray-500">
                  Action Taken
                </span>
              </th>
            </tr>
            {/* Column Headers */}
            <tr>
              <th className="px-6 py-3 font-medium">Timestamp</th>
              <th className="px-6 py-3 font-medium">Source IP</th>
              <th className="px-6 py-3 font-medium">Target</th>
              <th className="px-6 py-3 font-medium">Attack Type</th>
              <th className="px-6 py-3 font-medium">Severity</th>
              <th className="px-6 py-3 font-medium">Status Code</th>
              <th className="px-6 py-3 font-medium">Result</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {paginatedData.length > 0 ? (
              paginatedData.map((attack, idx) => {
                const isBreach =
                  attack.status === "Success" || attack.status_code === 200;

                return (
                  <tr
                    key={idx}
                    className={`hover:bg-white/[0.02] transition-colors ${
                      isBreach
                        ? "bg-red-900/10 border-l-2 border-l-red-500"
                        : "border-l-2 border-l-transparent"
                    }`}
                  >
                    <td className="px-6 py-4 font-mono text-gray-500 text-xs whitespace-nowrap">
                      {attack.timestamp || ""}
                    </td>
                    <td
                      className="px-6 py-4 font-mono text-blue-400 cursor-pointer hover:underline"
                      onClick={() =>
                        attack.ip &&
                        navigator.clipboard.writeText(attack.ip)
                      }
                    >
                      {attack.ip}
                    </td>
                    <td
                      className="px-6 py-4 text-gray-300 truncate max-w-[200px] font-mono text-xs"
                      title={attack.target}
                    >
                      {attack.target}
                    </td>
                    <td className="px-6 py-4 font-medium text-white">
                      {attack.type}
                    </td>
                    <td className="px-6 py-4">
                      {getSeverityBadge(attack.severity)}
                    </td>
                    <td className="px-6 py-4 font-mono text-gray-400 text-sm">
                      {attack.status_code || "--"}
                    </td>
                    <td className="px-6 py-4">
                      {getVerdictBadge(
                        attack.status,
                        attack.result,
                        attack.status_code
                      )}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={7} className="text-center py-12 text-gray-500">
                  No matching logs found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="flex items-center justify-between text-xs text-gray-600 px-1 mt-2">
        <span>
          Showing {filteredData.length === 0 ? 0 : startIndex + 1}-
          {Math.min(startIndex + itemsPerPage, filteredData.length)} of{" "}
          {filteredData.length} events
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => handlePageChange(currentPage - 1)}
            disabled={currentPage === 1}
            className="p-1 rounded hover:bg-white/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-gray-400">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => handlePageChange(currentPage + 1)}
            disabled={currentPage === totalPages}
            className="p-1 rounded hover:bg-white/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
