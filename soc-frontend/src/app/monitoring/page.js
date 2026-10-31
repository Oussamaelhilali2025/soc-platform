"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";

export default function MonitoringPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState("windows");

  const grafanaUrl =
    process.env.NEXT_PUBLIC_GRAFANA_URL || "http://localhost:3000";

  const dashboards = {
    windows: `${grafanaUrl}/d/ad8vzkp/windows-monitoring?orgId=1&kiosk=1&refresh=1m`,
    ubuntu: `${grafanaUrl}/goto/st6btg?orgId=default`,
  };

  return (
    <div className="flex min-h-screen w-full flex-col bg-slate-950 p-6 text-slate-100">

      {/* Header */}
      <div className="mb-6 flex items-center justify-between">

        <div>
          {/* Retour Dashboard */}
          <button
            type="button"
            onClick={() => router.push("/dashboard")}
            className="mb-3 inline-flex items-center gap-2 text-xs text-slate-500 transition-colors hover:text-cyan-400"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Retour au dashboard
          </button>

          <h1 className="text-2xl font-semibold text-white">
            Monitoring
          </h1>

          <p className="text-sm text-slate-400">
            Supervision globale de l'infrastructure
          </p>
        </div>

        {/* Sélection de l'actif */}
        <div className="flex gap-2 rounded-lg border border-slate-800 bg-slate-900 p-1">

          <button
            onClick={() => setActiveTab("windows")}
            className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === "windows"
                ? "bg-blue-600 text-white"
                : "text-slate-400 hover:text-white"
            }`}
          >
            POST-A
          </button>

          <button
            onClick={() => setActiveTab("ubuntu")}
            className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === "ubuntu"
                ? "bg-blue-600 text-white"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Serveu Web
          </button>

        </div>
      </div>

      {/* Dashboard Grafana */}
      <div className="w-full flex-1 overflow-hidden rounded-xl border border-slate-800 bg-[#0b0e14] shadow-lg">

        <iframe
          src={dashboards[activeTab]}
          title={`${activeTab} Monitoring`}
          className="h-[calc(100vh-150px)] w-full border-0"
          allow="fullscreen"
        />

      </div>
    </div>
  );
}