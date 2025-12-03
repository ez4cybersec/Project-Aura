import React from 'react';

export default function KibanaDashboard({ dashboardId = "aura-main", height = "800px" }) {
    // Default to localhost if env var not set
    const kibanaBase = import.meta.env.VITE_KIBANA_URL || "http://localhost:5601";
    
    // Construct embed URL
    // embed=true removes the side nav
    // hide-filter-bar=true removes the top filter bar
    const src = `${kibanaBase}/app/kibana#/dashboard/${dashboardId}?embed=true&_g=(refreshInterval:(pause:!f,value:5000),time:(from:now-15m,to:now))&_a=(description:'',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:''),timeRestore:!f,title:'Aura%20Threat%20Dashboard',viewMode:view)`;

    return (
        <div className="w-full bg-black/40 border border-white/10 rounded-xl overflow-hidden shadow-lg">
            <div className="p-4 border-b border-white/10 flex justify-between items-center">
                <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                    📊 Live Threat Intelligence (Kibana)
                </h3>
                <span className="text-xs text-gray-500">Connected to: {kibanaBase}</span>
            </div>
            <div className="relative w-full" style={{ height }}>
                <iframe
                    src={src}
                    className="absolute inset-0 w-full h-full border-none"
                    title="Kibana Dashboard"
                    loading="lazy"
                />
            </div>
        </div>
    );
}
