import React, { useState, useEffect, useMemo } from 'react';
import { Shield, AlertTriangle, Activity, Server, Lock } from 'lucide-react';
import StatCard from '../components/StatCard';
import ThreatDonut from '../components/ThreatDonut';
import AttackMap from '../components/AttackMap';
import ThreatLogTable from '../components/ThreatLogTable';
import { mockAttacks } from '../lib/mock-data';

export default function Dashboard() {
    const [traffic, setTraffic] = useState([]);
    const [searchTerm, setSearchTerm] = useState("");

    useEffect(() => {
        // Simulate loading data
        setTraffic(mockAttacks);
    }, []);

    // Filter Logic
    const filteredTraffic = useMemo(() => {
        if (!searchTerm) return traffic;
        const lowerTerm = searchTerm.toLowerCase();
        return traffic.filter(t =>
            (t.type && t.type.toLowerCase().includes(lowerTerm)) ||
            (t.ip && t.ip.includes(lowerTerm)) ||
            (t.status && t.status.toLowerCase().includes(lowerTerm))
        );
    }, [traffic, searchTerm]);

    const stats = useMemo(() => {
        const dataToUse = filteredTraffic; // Use filtered data for stats to make "all dynamic"
        const total = dataToUse.length;
        const threats = dataToUse.filter(t => t.severity === 'High' || t.severity === 'Critical').length;
        const breaches = dataToUse.filter(t => {
            const size = parseFloat(t.response_size);
            return t.status_code === 200 && size > 5 && (t.severity === 'High' || t.severity === 'Critical');
        }).length;

        return {
            total,
            threats,
            breaches,
            health: Math.max(0, 100 - (threats * 2))
        };
    }, [filteredTraffic]);

    return (
        <div className="p-6 space-y-6 pt-24 min-h-screen">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                    title="Total Events"
                    value={stats.total.toLocaleString()}
                    icon={Activity}
                    trend={searchTerm ? "Filtered" : "+12%"}
                    color="text-blue-500"
                />
                <StatCard
                    title="Threats Detected"
                    value={stats.threats.toLocaleString()}
                    icon={AlertTriangle}
                    trend={searchTerm ? "Filtered" : "+5%"}
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

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                    <AttackMap />
                </div>
                <div>
                    <ThreatDonut data={filteredTraffic} />
                </div>
            </div>

            <div className="bg-black/40 border border-white/10 rounded-xl overflow-hidden backdrop-blur-sm">
                <ThreatLogTable
                    attacks={filteredTraffic}
                    onSearch={setSearchTerm}
                />
            </div>
        </div>
    );
}
