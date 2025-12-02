import React, { useState, useEffect, useMemo } from "react";
import { AlertTriangle, Activity, Server, Lock } from "lucide-react";

import StatCard from "../components/StatCard";
import ThreatDonut from "../components/ThreatDonut";
import AttackMap from "../components/AttackMap";
import ThreatLogTable from "../components/ThreatLogTable";
import AttackExplanation from "../components/AttackExplanation";
import AttackTypeSummary from "../components/AttackTypeSummary";
import { apiClient } from "../lib/apiClient";
export default function Dashboard() {
    
  const [traffic, setTraffic] = useState([]);   // full attack list from backend
  const [mapData, setMapData] = useState([]);   // data for AttackMap
  const [stats, setStats] = useState({
    total: 0,
    threats: 0,
    breaches: 0,
    health: 100,
  });
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedAttack, setSelectedAttack] = useState(null); // for BERT panel

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [attacksData, statsData, trafficData] = await Promise.all([
          apiClient.getAttacks(),
          apiClient.getStats(),
          apiClient.getAttackTraffic(),
        ]);

        const safeAttacks = attacksData || [];
        const safeStats =
          statsData || { total: 0, threats: 0, breaches: 0, health: 100 };
        const safeTraffic = trafficData || [];

        setTraffic(safeAttacks);
        setStats(safeStats);

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

  // Filtered list for donut + table only
  const filteredTraffic = useMemo(() => {
    if (!searchTerm) return traffic;
    const lowerTerm = searchTerm.toLowerCase();
    return traffic.filter(
      (t) =>
        (t.type && t.type.toLowerCase().includes(lowerTerm)) ||
        (t.ip && t.ip.includes(lowerTerm)) ||
        (t.status && t.status.toLowerCase().includes(lowerTerm))
    );
  }, [traffic, searchTerm]);
   return (
    <div className="p-6 space-y-6 pt-24 min-h-screen">
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
          trend={searchTerm ? "Filtered" : "Live"}
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
          <ThreatDonut data={filteredTraffic} />

        </div>
      </div>

      {/* Live threat stream table */}
      <div className="bg-black/40 border border-white/10 rounded-xl overflow-hidden backdrop-blur-sm">
        <ThreatLogTable
        attacks={filteredTraffic}

          onSearch={setSearchTerm}
          onSelectAttack={setSelectedAttack}   // used by BERT XAI panel

        />
      </div>

      {/* Per-event BERT explanation */}
      <AttackExplanation selectedAttack={selectedAttack} />

      {/* Global attack-type + mitigation summary for this PCAP */}
      <AttackTypeSummary attacks={traffic} />
    </div>
  );
}