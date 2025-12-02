import React, { useState, useEffect, useMemo } from "react";
import { useLocation } from "react-router-dom";
import { AlertTriangle, Activity, Server, Lock, Loader2, CheckCircle2, RefreshCw } from "lucide-react";

import StatCard from "../components/StatCard";
import ThreatDonut from "../components/ThreatDonut";
import AttackMap from "../components/AttackMap";
import ThreatLogTable from "../components/ThreatLogTable";
import AttackExplanation from "../components/AttackExplanation";
import AttackTypeSummary from "../components/AttackTypeSummary";
import { apiClient } from "../lib/apiClient";
import { detectionType } from "../utils/detectionType";

const STAGE_DELAY_MS = Number(import.meta.env.VITE_STAGE_DELAY_MS) || 2500;

export default function Dashboard() {
  const location = useLocation();
  const [traffic, setTraffic] = useState([]);   // full attack list from backend
  const [mapData, setMapData] = useState([]);   // data for AttackMap
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedAttack, setSelectedAttack] = useState(null); // for BERT panel
  const [lastRefreshed, setLastRefreshed] = useState(null);

  // Staged Display State
  // 'regex' = Show only Regex/Pattern detections
  // 'ml'    = Show Regex + ML (Naive Bayes)
  // 'bert'  = Show everything (Regex + ML + BERT)
  const [displayStage, setDisplayStage] = useState(() => {
    return location.state?.justScanned ? 'regex' : 'bert';
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [attacksData, statsData, trafficData] = await Promise.all([
          apiClient.getAttacks(),
          apiClient.getStats(),
          apiClient.getAttackTraffic(),
        ]);

        const safeAttacks = attacksData || [];
        const safeTraffic = trafficData || [];

        setTraffic(safeAttacks);
        setLastRefreshed(new Date());

        if (safeTraffic.length > 0) {
          setMapData(safeTraffic);
        } else {
          setMapData(safeAttacks);
        }
      } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
      }
    };

    fetchData();
  }, []);

  // Transition Sequence: Regex -> ML -> BERT
  useEffect(() => {
    if (displayStage === 'regex') {
      const timer = setTimeout(() => {
        setDisplayStage('ml');
      }, STAGE_DELAY_MS);
      return () => clearTimeout(timer);
    }
    if (displayStage === 'ml') {
      const timer = setTimeout(() => {
        setDisplayStage('bert');
      }, STAGE_DELAY_MS);
      return () => clearTimeout(timer);
    }
  }, [displayStage]);

  // Filter traffic based on Stage + Search
  const visibleTraffic = useMemo(() => {
    let data = traffic;

    // 1. Stage Filtering using robust utility
    if (displayStage === 'regex') {
      data = data.filter(t => detectionType(t.evidence) === 'regex');
    } else if (displayStage === 'ml') {
      data = data.filter(t => {
        const type = detectionType(t.evidence);
        return type === 'regex' || type === 'ml';
      });
    }
    // 'bert' shows everything

    // 2. Search Filtering
    if (searchTerm) {
      const lowerTerm = searchTerm.toLowerCase();
      data = data.filter(
        (t) =>
          (t.type && t.type.toLowerCase().includes(lowerTerm)) ||
          (t.ip && t.ip.includes(lowerTerm)) ||
          (t.status && t.status.toLowerCase().includes(lowerTerm))
      );
    }

    return data;
  }, [traffic, displayStage, searchTerm]);

  // Recalculate stats based on VISIBLE traffic
  const stats = useMemo(() => {
    const total = traffic.length; // Total events is always full count
    const threats = visibleTraffic.length;

    // Count breaches in visible traffic
    const breachTypes = [
      "Command Injection", "SSRF", "Directory Traversal / LFI",
      "Remote File Inclusion (RFI)", "Shell Upload Attempt", "Bruteforce Attack"
    ];
    const breaches = visibleTraffic.filter(t => breachTypes.includes(t.type)).length;

    // Calculate health based on visible threats
    let health = 100;
    if (total > 0) {
      const risk = Math.min(100, Math.floor((threats / total) * 100));
      health = Math.max(0, 100 - risk);
    }

    return { total, threats, breaches, health };
  }, [traffic, visibleTraffic]);

  return (
    <div className="p-6 space-y-6 pt-24 min-h-screen">

      {/* Header with Timestamp and Override */}
      <div className="flex justify-between items-center mb-4">
        <div className="flex items-center gap-2 text-gray-400 text-sm">
          <RefreshCw className="w-4 h-4" />
          <span>Last Refreshed: {lastRefreshed ? lastRefreshed.toLocaleTimeString() : 'Syncing...'}</span>
        </div>

        {displayStage !== 'bert' && (
          <button
            onClick={() => setDisplayStage('bert')}
            className="px-4 py-2 bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 text-sm font-bold rounded-lg border border-blue-500/30 transition-all"
          >
            Show Full Results
          </button>
        )}
      </div>

      {/* Status Banner for Staged Analysis - Accessible */}
      <div role="status" aria-live="polite">
        {displayStage === 'regex' && (
          <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4 flex items-center gap-3 animate-in fade-in slide-in-from-top-4 duration-500">
            <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
            <div>
              <h3 className="text-blue-400 font-bold text-sm">Regex Analysis Complete</h3>
              <p className="text-blue-300/70 text-xs">Running Machine Learning (Naive Bayes) models...</p>
            </div>
          </div>
        )}

        {displayStage === 'ml' && (
          <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4 flex items-center gap-3 animate-in fade-in slide-in-from-top-4 duration-500">
            <Loader2 className="w-5 h-5 text-purple-400 animate-spin" />
            <div>
              <h3 className="text-purple-400 font-bold text-sm">ML Analysis Complete</h3>
              <p className="text-purple-300/70 text-xs">Initializing Deep Learning (BERT) models for final verification...</p>
            </div>
          </div>
        )}

        {displayStage === 'bert' && location.state?.justScanned && (
          <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4 flex items-center gap-3 animate-in fade-in slide-in-from-top-4 duration-500">
            <CheckCircle2 className="w-5 h-5 text-green-400" />
            <div>
              <h3 className="text-green-400 font-bold text-sm">Deep Analysis Complete</h3>
              <p className="text-green-300/70 text-xs">All threats identified including AI-detected anomalies.</p>
            </div>
          </div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Events"
          value={stats.total.toLocaleString()}
          icon={Activity}
          trend={searchTerm ? "Filtered" : "Live"}
          color="text-blue-500"
        />
        <StatCard
          title="Threats Detected"
          value={stats.threats.toLocaleString()}
          icon={AlertTriangle}
          trend={displayStage === 'bert' ? "Final" : "Analyzing..."}
          color="text-yellow-500"
        />
        <StatCard
          title="Active Breaches"
          value={stats.breaches.toLocaleString()}
          icon={Lock}
          trend={stats.breaches > 0 ? "CRITICAL" : "SECURE"}
          color="text-red-500"
          className={stats.breaches > 0 ? "animate-pulse border-red-500/50" : ""}
        />
        <StatCard
          title="System Health"
          value={`${stats.health}%`}
          icon={Server}
          trend="Stable"
          color="text-green-500"
        />
      </div>

      {/* Map + donut row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AttackMap data={mapData} />
        </div>
        <div>
          <ThreatDonut data={visibleTraffic} />
        </div>
      </div>

      {/* Live threat stream table */}
      <div className="bg-black/40 border border-white/10 rounded-xl overflow-hidden backdrop-blur-sm">
        <ThreatLogTable
          attacks={visibleTraffic}
          onSearch={setSearchTerm}
          onSelectAttack={setSelectedAttack}   // used by BERT panel
        />
      </div>

      {/* Per-event BERT explanation */}
      <AttackExplanation selectedAttack={selectedAttack} />

      {/* Global attack-type + mitigation summary for this PCAP */}
      <AttackTypeSummary attacks={traffic} />
    </div>
  );
}
