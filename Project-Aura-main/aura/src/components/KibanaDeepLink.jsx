import React from 'react';
import { ExternalLink, Lock } from 'lucide-react';

export default function KibanaDeepLink({ scanId }) {
    const kibanaBase = import.meta.env.VITE_KIBANA_URL || "http://localhost:5601";
    const indexPattern = "aura-attacks";

    if (!scanId) {
        return (
            <button
                disabled
                className="group flex items-center gap-2 px-4 py-2 bg-black/40 backdrop-blur-sm border border-gray-800 text-gray-500 font-mono text-sm rounded-lg cursor-not-allowed transition-all"
                title="Run a scan to enable Kibana analysis"
            >
                <Lock className="w-4 h-4 opacity-50 group-hover:text-red-500/50 transition-colors" />
                <span className="tracking-wider">ANALYSIS LOCKED</span>
            </button>
        );
    }

    // RISON-encoded Global State (_g) to PIN the filter
    const filterRison = `(filters:!((meta:(alias:!n,disabled:!f,index:'${indexPattern}',key:scan_id,negate:!f,params:(query:'${scanId}'),type:phrase),query:(match:(scan_id:(query:'${scanId}',type:phrase))))))`;

    // We attach this to the Global State (_g) parameter
    const targetUrl = `${kibanaBase}/app/discover#/?_g=${filterRison}&_a=(columns:!(attack_type,severity,action,source_ip,url),interval:auto,sort:!(!('@timestamp',desc)))`;

    return (
        <a
            href={targetUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="group flex items-center gap-2 px-5 py-2 bg-cyan-950/30 backdrop-blur-md border border-cyan-500/50 text-cyan-400 font-mono text-sm font-bold rounded-lg transition-all hover:bg-cyan-500/10 hover:shadow-[0_0_20px_rgba(6,182,212,0.3)] hover:border-cyan-400"
        >
            <ExternalLink className="w-4 h-4 group-hover:rotate-45 transition-transform duration-300" />
            <span className="tracking-widest">OPEN KIBANA INTEL</span>
        </a>
    );
}
